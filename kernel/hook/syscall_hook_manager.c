#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/jump_label.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/thread_info.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/compat.h>

#include "arch.h"
#include "klog.h"
extern void ksu_blog(const char *fmt, ...);   /* KSU_X86_BOOT_LOG */ // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#if defined(__riscv)
#include "hook/riscv64/syscall_regs.h"
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    if (ksu_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    ksu_tp_marker_inc_reg_count();
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    ksu_tp_marker_dec_reg_count();
    if (ksu_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
/* [KSU-X86-PORT][DIAG] tracepoint -> dispatcher -> hook 链路计数（临时） */
unsigned long ksu_tp_calls, ksu_tp_compat, ksu_tp_nohook, ksu_tp_redir;
unsigned long ksu_disp_calls, ksu_disp_bad;
unsigned long ksu_hook_setresuid_calls;

static void ksu_tp_diag_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_tp_diag_work, ksu_tp_diag_fn);
static int ksu_tp_diag_left = 20;

extern struct tracepoint __tracepoint_sys_enter;

static void ksu_tp_diag_fn(struct work_struct *w)
{
    struct task_struct *p, *t;
    int tp_set = 0, tp_total = 0;

    read_lock(&tasklist_lock);
    for_each_process_thread(p, t) {
        tp_total++;
        if (test_task_syscall_work(t, SYSCALL_TRACEPOINT))
            tp_set++;
    }
    read_unlock(&tasklist_lock);

    ksu_blog("TPDIAG calls=%lu compat=%lu nohook=%lu redir=%lu disp=%lu bad=%lu hook=%lu key=%d tpset=%d/%d\n",
             ksu_tp_calls, ksu_tp_compat, ksu_tp_nohook, ksu_tp_redir,
             ksu_disp_calls, ksu_disp_bad, ksu_hook_setresuid_calls,
             static_key_enabled(&__tracepoint_sys_enter.key), tp_set, tp_total);
    if (--ksu_tp_diag_left > 0)
        schedule_delayed_work(&ksu_tp_diag_work, msecs_to_jiffies(15000));
}

// sys_enter handler: redirect hooked syscalls to the dispatcher
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
    ksu_tp_calls++;

#if defined(__x86_64__)
    if (unlikely(in_compat_syscall())) {
        ksu_tp_compat++;
#elif defined(__aarch64__) || defined(__riscv)
    if (unlikely(is_compat_task())) {
        ksu_tp_compat++;
#endif
        return;
    }

    if (ksu_dispatcher_nr < 0)
        return;

    if (ksu_has_syscall_hook(id)) {
        ksu_tp_redir++;
#if defined(__x86_64__)
        /* [KSU-X86-PORT] 直接用 tracepoint 传入的 regs。
         * FRED（CONFIG_X86_FRED=y）下 task_pt_regs(current) 不一定等于
         * 入口实际使用/回读的那份 pt_regs；用 regs 才能保证改写生效。 */
        regs->ax = id;
        regs->orig_ax = ksu_dispatcher_nr;
#elif defined(__aarch64__)
        struct pt_regs *current_regs = task_pt_regs(current);
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = ksu_dispatcher_nr;
#elif defined(__riscv)
        struct pt_regs *current_regs = task_pt_regs(current);
        /* orig_a0 retains argument zero; a0 is the -ENOSYS return slot. */
        ksu_riscv_redirect_syscall(current_regs, id, ksu_dispatcher_nr);
#endif
    } else {
        ksu_tp_nohook++;
    }
}
#endif

void  ksu_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: ksu_hook_manager_init called\n");

#ifdef CONFIG_KRETPROBES
    syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
#endif

    // Register syscall hooks via dispatcher
    ksu_register_syscall_hook(__NR_setresuid, ksu_hook_setresuid);
    ksu_register_syscall_hook(__NR_execve, ksu_hook_execve);
    ksu_register_syscall_hook(__NR_execveat, ksu_hook_execveat);
    ksu_register_syscall_hook(__NR_newfstatat, ksu_hook_newfstatat);
    ksu_register_syscall_hook(__NR_faccessat, ksu_hook_faccessat);

    ksu_blog("hook_manager: setresuid hooked=%d execve=%d\n",
             ksu_has_syscall_hook(__NR_setresuid), ksu_has_syscall_hook(__NR_execve));

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
        ksu_blog("hook_manager: sys_enter tracepoint FAILED ret=%d\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\n");
        ksu_blog("hook_manager: sys_enter tracepoint registered\n");
    }

    /* [KSU-X86-PORT][DIAG] 兜底：确保所有任务都带 SYSCALL_TRACEPOINT 工作位。
     * tracepoint 的 regfunc 只在 static key 首次启用时执行；若 key 已被别的
     * tracer 提前启用，新任务之外的位可能不完整。这里幂等补一次。 */
    {
        struct task_struct *p, *t;
        read_lock(&tasklist_lock);
        for_each_process_thread(p, t)
            set_task_syscall_work(t, SYSCALL_TRACEPOINT);
        read_unlock(&tasklist_lock);
    }
#endif

    ksu_setuid_hook_init();
    ksu_sucompat_init();

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    /* [KSU-X86-PORT][DIAG] 15s 后开始周期性输出链路计数，共 8 次 */
    INIT_DELAYED_WORK(&ksu_tp_diag_work, ksu_tp_diag_fn);
    schedule_delayed_work(&ksu_tp_diag_work, msecs_to_jiffies(15000));
#endif
}

void __exit ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    ksu_unregister_syscall_hook(__NR_setresuid);
    ksu_unregister_syscall_hook(__NR_execve);
    ksu_unregister_syscall_hook(__NR_execveat);
    ksu_unregister_syscall_hook(__NR_newfstatat);
    ksu_unregister_syscall_hook(__NR_faccessat);

    ksu_syscall_hook_exit();

    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
