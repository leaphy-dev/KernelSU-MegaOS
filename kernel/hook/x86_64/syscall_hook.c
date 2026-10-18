#ifdef __x86_64__

#include "../syscall_hook.h"

#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/moduleloader.h>
#include <asm/set_memory.h>
#include <linux/mutex.h>
#include <linux/nospec.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/kmsg_dump.h>
#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include "manager/manager_identity.h"
#include "supercall/supercall.h"
#include "infra/symbol_resolver.h"
#include "../patch_memory.h"
#include "arch.h"
#include "klog.h"
extern void ksu_blog(const char *fmt, ...);
#include "shim/ksu_shim.h"   /* [KSU-X86-PORT] ksu_ibt_ensure_endbr */

/* [KSU-X86-PORT] 统一入口：先修 ENDBR，再间接调用。 */
long ksu_call_syscall(int nr, const struct pt_regs *regs)
{
    sys_call_ptr_t fn = READ_ONCE(ksu_syscall_table[nr]);
    ksu_ibt_ensure_endbr((void *)fn);
    return fn(regs);
}

/* ============================================================================
 * [KSU-X86-PORT] 本文件的非上游改动清单（H3C MegaBook / MegaOS / 6.12.30）
 *
 * 约定：所有非上游改动一律以 [KSU-X86-PORT] 标注，并写清
 *       「改了什么 / 为什么（证据）/ 不改会怎样」；改逻辑时保留原逻辑注释，便于回退。
 *
 * 关键背景（均为设备实测）：
 *  1) 6.12 的 x64_sys_call 是【生成的 switch】，不引用 sys_call_table；
 *     但 sys_call_table 本身仍是正确的（[0]=__x64_sys_read，[1]=__x64_sys_write）。
 *  2) 入口前 4 字节运行时有两种形态：endbr64，或被 IBT 封存成 4 字节 NOP
 *     （实测 66 0f 1f 00）⇒ 必须无条件跳过 4 字节，否则 12 字节窗口整体错位。
 *  3) 补丁必须落在指令边界：+4 处为 nopl(5) + mov(7) = 12 字节；14 会切进 cmp。
 *  4) 内核开了 IBT：蹦床需 endbr64 开头；回跳函数中间只能用 ret，不能间接 jmp。
 *  5) 被覆盖的 mov $-ENOSYS,%rax 决定默认返回值 ⇒ 回跳前必须保留 rax。
 *
 * 改动列表：
 *  - KSU_X64_PATCH_LEN=12；补丁改为 movabs rax,target + jmp rax
 *  - prepare_abs_jump / install_abs_jump 拆分：先校验/备份，再安装
 *  - 原地蹦床（vmalloc + set_memory_x）：endbr64 + 12B 回放 + push/movabs/xchg/ret
 *  - 非 dispatcher 调用走蹦床（交回内核自己的 switch），不再自行用表派发
 *  - ksu_blog() 双通道日志（persistent@512KB / /data/local/tmp）
 * ========================================================================== */

sys_call_ptr_t *ksu_syscall_table = NULL;
int ksu_dispatcher_nr = -1;

#ifndef __NR_syscalls
#define __NR_syscalls (__NR_syscall_max + 1)
#endif

// Hook registration table — read with READ_ONCE from tracepoint/dispatcher
// context, written with WRITE_ONCE from init/exit context.
static ksu_syscall_hook_fn syscall_hooks[__NR_syscalls];

// Track all hooked syscall entries for restoration.
// Protected by hooked_entries_lock.
struct syscall_hook_entry {
    int nr;
    sys_call_ptr_t orig;
};

static DEFINE_MUTEX(hooked_entries_lock);
static struct syscall_hook_entry hooked_entries[16];
static int hooked_count = 0;

static int patch_syscall_table(int nr, sys_call_ptr_t fn)
{
    ksu_blog("   patch_syscall_table: enter nr=%d\n", nr);
    if (ksu_syscall_table == NULL)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;

    pr_info("patch syscall %d, 0x%lx -> 0x%lx\n", nr, (unsigned long)READ_ONCE(ksu_syscall_table[nr]),
            (unsigned long)fn);

    ksu_blog("   patch_syscall_table: about to call ksu_patch_text dst=%lx\n", (unsigned long)&ksu_syscall_table[nr]);
    if (ksu_patch_text(&ksu_syscall_table[nr], &fn, sizeof(fn), KSU_PATCH_TEXT_FLUSH_DCACHE)) {
        pr_err("patch syscall %d failed\n", nr);
        return -EIO;
    }

    return 0;
}

// Direct syscall table patching: overwrite syscall_table[nr] with fn,
// save original to *old, and record for restoration at module exit.
void ksu_syscall_table_hook(int nr, sys_call_ptr_t fn, sys_call_ptr_t *old)
{
    ksu_blog("   table_hook: enter nr=%d\n", nr);
    if (ksu_syscall_table == NULL)
        return;
    if (nr < 0 || nr >= __NR_syscalls) {
        pr_info("invalid nr: %d\n", nr);
        return;
    }

    ksu_blog("   table_hook: locking\n");
    mutex_lock(&hooked_entries_lock);
    ksu_blog("   table_hook: locked\n");

    sys_call_ptr_t orig = READ_ONCE(ksu_syscall_table[nr]);
    if (old)
        *old = orig;

    // Record for later restoration
    int i;
    bool found = false;
    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            found = true;
            break;
        }
    }
    if (!found) {
        if (hooked_count < ARRAY_SIZE(hooked_entries)) {
            hooked_entries[hooked_count].nr = nr;
            hooked_entries[hooked_count].orig = orig;
            hooked_count++;
        } else {
            pr_warn("hooked_entries full, cannot track syscall %d for restoration\n", nr);
        }
    }

    ksu_blog("   table_hook: calling patch_syscall_table\n");
    patch_syscall_table(nr, fn);
    ksu_blog("   table_hook: patch_syscall_table returned\n");

    mutex_unlock(&hooked_entries_lock);
}

// Restore syscall_table[nr] to its original value and remove from tracking list.
void ksu_syscall_table_unhook(int nr)
{
    int i;

    if (ksu_syscall_table == NULL)
        return;
    if (nr < 0 || nr >= __NR_syscalls)
        return;

    mutex_lock(&hooked_entries_lock);

    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            patch_syscall_table(nr, hooked_entries[i].orig);
            // Remove entry by swapping with last
            hooked_entries[i] = hooked_entries[--hooked_count];
            mutex_unlock(&hooked_entries_lock);
            pr_info("unhooked syscall %d\n", nr);
            return;
        }
    }

    mutex_unlock(&hooked_entries_lock);
    pr_warn("syscall %d not found in hooked entries\n", nr);
}

static int ksu_find_ni_syscall_slots(int *out_slots, int max_slots)
{
    unsigned long ni_syscall;
    int i, count = 0;

    if (!ksu_syscall_table || max_slots <= 0)
        return 0;

    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook("__x64_sys_ni_syscall");

    pr_info("sys_ni_syscall: 0x%lx\n", ni_syscall);

    if (!ni_syscall)
        return 0;

    for (i = 0; i < __NR_syscalls && count < max_slots; i++) {
        if ((unsigned long)ksu_syscall_table[i] == ni_syscall) {
            out_slots[count++] = i;
            pr_info("ni_syscall %d: %d\n", count, i);
        }
    }

    return count;
}

// Unified dispatcher: reads original NR from orig_ax, dispatches to handler.
// Validates that orig_ax matches our dispatcher slot (i.e. we redirected it),
// otherwise it's a spurious call — return -ENOSYS.
static long __nocfi ksu_syscall_dispatcher(const struct pt_regs *regs)
{
    if (regs->orig_ax != ksu_dispatcher_nr)
        return -ENOSYS;

    // On x86_64, orig_ax was overwritten by our tracepoint to route here.
    // The original syscall number passed by userspace is still sitting untouched in ax.
    int orig_nr = (int)regs->ax;

    if (regs->orig_ax == orig_nr)
        return -ENOSYS;

    // Restore registers to original state before dispatching
    ((struct pt_regs *)regs)->orig_ax = orig_nr;

    if (likely(orig_nr >= 0 && orig_nr < __NR_syscalls)) {
        ksu_syscall_hook_fn fn = READ_ONCE(syscall_hooks[orig_nr]);
        if (likely(fn))
            return fn(orig_nr, regs);
    }

    return -ENOSYS;
}

// Register a handler into the dispatcher's routing table.
// Does not modify the syscall table — the dispatcher slot is shared by all hooks.
int ksu_register_syscall_hook(int nr, ksu_syscall_hook_fn fn)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    if (READ_ONCE(syscall_hooks[nr])) {
        pr_warn("syscall hook for nr=%d already registered, skip\n", nr);
        return -EEXIST;
    }
    WRITE_ONCE(syscall_hooks[nr], fn);
    pr_info("registered syscall hook for nr=%d\n", nr);
    return 0;
}

// Remove a handler from the dispatcher's routing table.
// The syscall table is not touched — only the dispatcher stops routing this nr.
void ksu_unregister_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return;
    WRITE_ONCE(syscall_hooks[nr], NULL);
    pr_info("unregistered syscall hook for nr=%d\n", nr);
}

bool ksu_has_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return false;
    return READ_ONCE(syscall_hooks[nr]) != NULL;
}

// https://github.com/torvalds/linux/commit/1e3ad78334a69b36e107232e337f9d693dcc9df2
// harden syscall table was introduced in 6.9, but it was backported to almost
// all of GKI kernel except 5.10
#ifdef CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER
static void *x64_sys_call_patch_addr;
/* [KSU-X86-PORT] x64_sys_call 的真实指令边界（由设备 vmlinux 反汇编确认）：
 *   +0x00  nopl 0x0(%rax,%rax,1)   5 B
 *   +0x05  mov  $-ENOSYS,%rax      7 B   -> 12 B 处正好是下一条指令起点
 *   +0x0c  cmp  $0xbd,%esi         6 B
 * 所以补丁长度必须是 12；14 会切在 cmp 中间（回放必然出错）。
 */
#define KSU_X64_PATCH_LEN 12

static void *ksu_tramp;                /* 原地蹦床：endbr64 + 12B 回放 + ret 回跳 */
static char x64_sys_call_patch_orig_insn[KSU_X64_PATCH_LEN];


#ifdef KSU_X86_BLACKBOX
/* [KSU-X86-PORT][DIAG] panic 时把内核日志（含 oops 回溯）写到
 * persistent@768KB。文件在 init 阶段预先打开，panic 路径只做 kernel_write，
 * 尽量避免在崩溃时做路径查找。 */
static struct file *ksu_panic_f;
static char *ksu_panic_buf;
static struct kmsg_dumper ksu_kd;

static void ksu_kd_dump(struct kmsg_dumper *d, struct kmsg_dump_detail *detail)
{
    struct kmsg_dump_iter iter;
    size_t len = 0;

    if (!ksu_panic_f || !ksu_panic_buf)
        return;

    /* 注意：必须用 get_buffer（取【尾部】），不能用 get_line 循环
     * —— 后者从最旧记录开始，128KB 会被开机早期日志塞满，看不到 panic。*/
    kmsg_dump_rewind(&iter);
    if (!kmsg_dump_get_buffer(&iter, true, ksu_panic_buf, 65536, &len) || !len)
        return;

    ksu_panic_f->f_pos = 768 * 1024;
    kernel_write(ksu_panic_f, ksu_panic_buf, len, &ksu_panic_f->f_pos);
}

#endif

static long my_x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
    /* KSU 只关心被 tracepoint 改写成 dispatcher 槽位的调用；其余交回内核 */
    if ((int)nr == ksu_dispatcher_nr)
        return ksu_syscall_dispatcher(regs);
    /* [KSU-X86-PORT] 管理器驱动 fd 的兜底注入：
     * 正常路径是 hook manager 的 setresuid 钩子（ksu_handle_setresuid）注入 fd；
     * 这里保留 execve 成功后的兜底（某些启动方式不经过 setresuid 钩子）。
     * 没有 fd 时管理器的 C++ ksuctl() 只扫描 /proc/self/fd，扫不到就直接返回
     * EBADF ⇒ 界面显示"未安装"。
     * 只对管理器 uid 生效；fd 带 O_CLOEXEC，下次 exec 会自动关闭并重新注入。 */
    if (nr == __NR_execve || nr == __NR_execveat) {
        long ret;

        if (!ksu_tramp)
            return -ENOSYS;
        ret = ((long (*)(const struct pt_regs *, unsigned int))ksu_tramp)(regs, nr);
        if (ret == 0 && is_manager()) {
            int fd = ksu_install_fd();
            ksu_blog("SUPER: manager fd=%d pid=%d (after execve)\n", fd, current->pid);
        }
        return ret;
    }

    /* [KSU-X86-PORT] 其余调用：走原地蹦床（回放被覆盖的 12 字节后跳回
     * x64_sys_call+12），由内核自己的 switch 完成派发。
     * 上游/KSU-Next 在这里用 ksu_syscall_table[nr](regs) 自行派发；
     * H3C MegaBook 14 实测该路径会在管理器启动时整机 panic（NR/表项与生成 switch 不完全一致），
     * 因此改为蹦床，完全不碰 sys_call_table。 */
    if (ksu_tramp)
        return ((long (*)(const struct pt_regs *, unsigned int))ksu_tramp)(regs, nr);
    return -ENOSYS;
}

// avd 13-5.15 missing this commit:
// https://github.com/torvalds/linux/commit/fb13b11d53875e28e7fbf0c26b288e4ea676aa9f
// we need to patch the whole do_syscall_64
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
static void *do_syscall_64_patch_addr;
static char do_syscall_64_orig_insn[14];

static long (*syscall_enter_from_user_mode_fn)(struct pt_regs *regs, long syscall);
static void (*syscall_exit_to_user_mode_fn)(struct pt_regs *regs);

static __always_inline bool my_do_syscall_x64(struct pt_regs *regs, int nr)
{
    /*
	 * Convert negative numbers to very high and thus out of range
	 * numbers for comparisons.
	 */
    unsigned int unr = nr;

    if (likely(unr < NR_syscalls)) {
        unr = array_index_nospec(unr, NR_syscalls);
        regs->ax = ksu_syscall_table[unr](regs);
        return true;
    }
    return false;
}

static void __nocfi my_do_syscall_64(struct pt_regs *regs, int nr)
{
    nr = syscall_enter_from_user_mode_fn(regs, nr);
    nr = syscall_get_nr(current, regs);

    // AVD doesn't have x32 support after A13, we can ignore do_syscall_x32

    if (!my_do_syscall_x64(regs, nr) && nr != -1) {
        /* Invalid system call, but still a system call. */
        regs->ax = -ENOSYS;
    }

    syscall_exit_to_user_mode_fn(regs);
}
#endif
#endif

/* 解析符号、校验前导字节、备份原始 12 字节；本函数不写内核代码。
 * 返回 0 表示可以安全打补丁。 */
static int prepare_abs_jump(const char *sym, void **patch_addr, char backup[KSU_X64_PATCH_LEN])
{
    *patch_addr = (void *)find_kernel_symbol_exact(sym);
    pr_info("%s=0x%lx\n", sym, (unsigned long)*patch_addr);
    if (!*patch_addr)
        return -ENOENT;

    /* [KSU-X86-PORT] 进入函数时先跳过开头的 4 字节。注意它有两种形态：
     *   - 静态 vmlinux：endbr64 (f3 0f 1e fa)
     *   - 运行时：IBT 封存会把非间接目标函数的 endbr64 替换成 4 字节 NOP
     *     (66 0f 1f 00)。二者都是 4 字节，跳过即可。
     * 这一步必须无条件执行 —— 之前按 endbr64 匹配失败就不跳，
     * 结果从 +0 开始比对，12 字节窗口整体错位（日志实测）。 */
    static const unsigned char entry_forms[][4] = {
        // clang-format off
        { 0xf3, 0x0f, 0x1e, 0xfa },   /* endbr64 */
        { 0x66, 0x0f, 0x1f, 0x00 },   /* IBT 封存后的 4 字节 NOP */
        // clang-format on
    };
    if (memcmp((void *)*patch_addr, entry_forms[0], 4) == 0) {
        pr_info("%s: skip endbr64\n", sym);
    } else if (memcmp((void *)*patch_addr, entry_forms[1], 4) == 0) {
        pr_info("%s: skip sealed endbr64 (nop)\n", sym);
    } else {
        pr_err("%s: unexpected entry bytes %02x %02x %02x %02x, abort\n", sym,
               ((unsigned char *)*patch_addr)[0], ((unsigned char *)*patch_addr)[1],
               ((unsigned char *)*patch_addr)[2], ((unsigned char *)*patch_addr)[3]);
        *patch_addr = NULL;
        return -EINVAL;
    }
    *patch_addr = (void *)((char *)(*patch_addr) + 4);
    /* 只对 x64_sys_call 做严格的前导字节校验：万一内核版本/编译选项不同，
     * 宁可放弃 hook 也绝不在指令中间打补丁（否则必崩）。 */
    if (strcmp(sym, "x64_sys_call") == 0) {
        static const unsigned char expect[KSU_X64_PATCH_LEN] = {
            // nopl 0x0(%rax,%rax,1) ; mov $-ENOSYS,%rax
            0x0f, 0x1f, 0x44, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff,
        };
        if (memcmp(*patch_addr, expect, sizeof(expect)) != 0) {
            pr_err("%s: prologue mismatch (%02x %02x %02x ...), abort hook\n", sym,
                   ((unsigned char *)*patch_addr)[0], ((unsigned char *)*patch_addr)[1],
                   ((unsigned char *)*patch_addr)[2]);
            *patch_addr = NULL;
            return -EINVAL;
        }
        pr_info("%s: prologue verified (12-byte boundary)\n", sym);
    }
    memcpy(backup, *patch_addr, KSU_X64_PATCH_LEN);
    return 0;
}

/* [KSU-X86-PORT] 写入 12 字节补丁：movabs rax, target ; jmp rax
 * （上游用的是 14 字节 `jmp *(%rip)`，在本内核会切在 cmp 指令中间）*/
static int install_abs_jump(void *patch_addr, void *target)
{
    // clang-format off
    char buf[KSU_X64_PATCH_LEN] = {
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, imm64
        0xff, 0xe0,                                                   // jmp rax
    };
    // clang-format on
    *(unsigned long *)(buf + 2) = (unsigned long)target;
    return ksu_patch_text(patch_addr, buf, sizeof(buf), KSU_PATCH_TEXT_FLUSH_ICACHE);
}

static void patch_abs_jump(const char *sym, void **patch_addr, void *target, char backup[KSU_X64_PATCH_LEN])
{
    if (prepare_abs_jump(sym, patch_addr, backup) != 0)
        return;
    int ret = install_abs_jump(*patch_addr, target);
    if (ret) {
        pr_err("patch %s err: %d\n", sym, ret);
        *patch_addr = NULL;
    }
}

void  __nocfi ksu_syscall_hook_init(void)
{
    int ni_slot;

#ifdef KSU_X86_BLACKBOX
    ksu_panic_buf = vmalloc(65536);
    ksu_panic_f = filp_open("/dev/block/by-name/persistent", O_WRONLY | O_SYNC, 0);
    if (IS_ERR(ksu_panic_f)) {
        ksu_panic_f = NULL;
        ksu_blog("KD: open persistent FAILED\n");
    } else {
        ksu_kd.dump = ksu_kd_dump;
        ksu_kd.max_reason = KMSG_DUMP_MAX;   /* 记录 panic/oops 等所有原因 */
        ksu_blog("KD: register=%d (panic log -> persistent@768KB)\n",
                 kmsg_dump_register(&ksu_kd));
    }
#endif

    memset(syscall_hooks, 0, sizeof(syscall_hooks));

    ksu_syscall_table = (sys_call_ptr_t *)ksu_resolve_symbol_for_functable_hook("sys_call_table");
    ksu_blog("  hook: sub-step sys_call_table=%lx\n", (unsigned long)ksu_syscall_table);
    pr_info("sys_call_table=0x%lx\n", (unsigned long)ksu_syscall_table);

    if (!ksu_syscall_table) {
        ksu_blog("  hook: sys_call_table NULL -> return\n");
        return;
    }

#ifdef CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER
    ksu_blog("  hook: sub-step prepare_abs_jump BEGIN\n");
    if (prepare_abs_jump("x64_sys_call", &x64_sys_call_patch_addr, x64_sys_call_patch_orig_insn) == 0) {
        /* [KSU-X86-PORT] 先建蹦床，再打补丁；否则别的 CPU 可能在本页就绪前跳进来。
         * 分配用 vmalloc + set_memory_x（H3C MegaBook 14 没有 module_alloc 符号，见踩坑记录 1.5）*/
        unsigned char *t = (unsigned char *)vmalloc(PAGE_SIZE);
        if (!t) {
            ksu_blog("  hook: trampoline vmalloc FAILED -> skip absjump\n");
            x64_sys_call_patch_addr = NULL;
        } else {
            unsigned char *p = t;
            unsigned long cont = (unsigned long)x64_sys_call_patch_addr + KSU_X64_PATCH_LEN;

            /* IBT：间接调用进入本页，必须以 endbr64 开头 */
            *p++ = 0xf3; *p++ = 0x0f; *p++ = 0x1e; *p++ = 0xfa;
            /* 回放被覆盖的 12 字节（nopl + mov $-ENOSYS,%rax） */
            memcpy(p, x64_sys_call_patch_orig_insn, KSU_X64_PATCH_LEN);
            p += KSU_X64_PATCH_LEN;
            /* 回跳函数中间不能用间接 jmp（IBT 要求目标有 endbr64），
             * 用 ret：push rax / movabs rax,cont / xchg rax,(rsp) / ret，
             * 既绕过 IBT，又完整保留 rax（原函数用它预置 -ENOSYS）。 */
            *p++ = 0x50;                                          /* push rax */
            *p++ = 0x48; *p++ = 0xb8;                             /* movabs rax, cont */
            *(unsigned long *)p = cont; p += 8;
            *p++ = 0x48; *p++ = 0x87; *p++ = 0x04; *p++ = 0x24;   /* xchg rax,(rsp) */
            *p++ = 0xc3;                                          /* ret */

            if (set_memory_x((unsigned long)t, 1) != 0) {
                ksu_blog("  hook: set_memory_x FAILED -> skip absjump\n");
                vfree(t);
                x64_sys_call_patch_addr = NULL;
            } else {
                ksu_tramp = t;
                ksu_blog("  hook: trampoline built @%lx cont=%lx len=%u\n",
                         (unsigned long)t, cont, (unsigned int)(p - t));
                if (install_abs_jump(x64_sys_call_patch_addr, my_x64_sys_call) == 0) {
                    ksu_blog("  hook: sub-step patch_abs_jump DONE addr=%lx\n",
                             (unsigned long)x64_sys_call_patch_addr);
                } else {
                    ksu_blog("  hook: patch_abs_jump FAILED\n");
                    ksu_tramp = NULL;
                    vfree(t);
                    x64_sys_call_patch_addr = NULL;
                }
            }
        }
    } else {
        ksu_blog("  hook: prepare_abs_jump FAILED -> absjump skipped\n");
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
    syscall_enter_from_user_mode_fn = find_kernel_symbol_exact("syscall_enter_from_user_mode");
    syscall_exit_to_user_mode_fn = find_kernel_symbol_exact("syscall_exit_to_user_mode");
    pr_info("syscall_enter_from_user_mode: 0x%lx, syscall_exit_to_user_mode: 0x%lx\n",
            (unsigned long)syscall_enter_from_user_mode_fn, (unsigned long)syscall_exit_to_user_mode_fn);
    if (syscall_enter_from_user_mode_fn && syscall_exit_to_user_mode_fn) {
        patch_abs_jump("do_syscall_64", &do_syscall_64_patch_addr, my_do_syscall_64, do_syscall_64_orig_insn);
    }
#endif
#endif

    // Find one ni_syscall slot for the dispatcher
    ksu_blog("  hook: sub-step find_ni_syscall_slots BEGIN\n");
    if (ksu_find_ni_syscall_slots(&ni_slot, 1) < 1) {
        pr_err("failed to find ni_syscall slot for dispatcher\n");
        return;
    }

    ksu_blog("  hook: sub-step ni_slot=%d\n", ni_slot);
    ksu_dispatcher_nr = ni_slot;
    /* [KSU-X86-PORT] 上游原逻辑：把 dispatcher 挂到 ni_syscall 表项上。
     * 但 H3C MegaBook 14 上这条路径【必崩】，实测（hmenable6，2026-10-18）：
     *   set_memory_rw(sys_call_table 所在 .rodata 页) 返回 0，
     *   页面实际仍为只读 ⇒ memcpy 触发
     *   #PF error_code(0x0003) supervisor write, CR2=sys_call_table+134*8
     *   ⇒ Oops ⇒ Kernel panic。
     * 而 6.9+ 的 x64_sys_call 是生成的 switch、不查 sys_call_table，
     * 该表项 patch 本就不生效；真正的派发由上面的 12 字节 abs jump 完成。
     * 故源码保留上游调用，仅在本设备构建时用 KSU_X86_SKIP_TABLE_HOOK 编译掉。 */
#ifndef KSU_X86_SKIP_TABLE_HOOK
    ksu_syscall_table_hook(ksu_dispatcher_nr, (sys_call_ptr_t)ksu_syscall_dispatcher, NULL);
#else
    ksu_blog("  hook: table_hook skipped (rodata RO; abs jump covers x64_sys_call)\n");
#endif
    ksu_blog("  hook: dispatcher installed at slot %d\n", ni_slot);
    pr_info("dispatcher installed at slot %d\n", ksu_dispatcher_nr);
}

void __exit ksu_syscall_hook_exit(void)
{
    int i;

#ifdef CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER
    int ret;
    if (x64_sys_call_patch_addr) {
        ret = ksu_patch_text((void *)x64_sys_call_patch_addr, x64_sys_call_patch_orig_insn,
                             sizeof(x64_sys_call_patch_orig_insn), KSU_PATCH_TEXT_FLUSH_ICACHE);
        if (ret) {
            pr_err("restore x64_sys_call err: %d\n", ret);
        }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
    if (do_syscall_64_patch_addr) {
        ret = ksu_patch_text((void *)do_syscall_64_patch_addr, do_syscall_64_orig_insn, sizeof(do_syscall_64_orig_insn),
                             KSU_PATCH_TEXT_FLUSH_ICACHE);
        if (ret) {
            pr_err("restore x64_sys_call err: %d\n", ret);
        }
    }
#endif
#endif

    if (!ksu_syscall_table)
        goto clear_state;

    // First, restore all patched syscall table entries while the dispatcher
    // and hook table are still intact, so in-flight syscalls see valid state.
    mutex_lock(&hooked_entries_lock);
    for (i = 0; i < hooked_count; i++) {
        int nr = hooked_entries[i].nr;
        sys_call_ptr_t orig = hooked_entries[i].orig;

        pr_info("restore syscall %d to 0x%lx\n", nr, (unsigned long)orig);
        if (ksu_patch_text(&ksu_syscall_table[nr], &orig, sizeof(orig), KSU_PATCH_TEXT_FLUSH_DCACHE)) {
            pr_err("restore syscall %d failed\n", nr);
        }
    }
    hooked_count = 0;
    mutex_unlock(&hooked_entries_lock);

clear_state:
    // Now that the syscall table is restored, clear internal state.
    // At this point the tracepoint is already unregistered and synchronized
    // (done by ksu_syscall_hook_manager_exit before calling us), so no new
    // dispatches will occur.
    memset(syscall_hooks, 0, sizeof(syscall_hooks));
    ksu_dispatcher_nr = -1;

    pr_info("all syscall hooks restored\n");
}

#endif /* __x86_64__ */
