
/* ============================================================================
 * [KSU-X86-PORT] 以下日志系统【不是 KernelSU 上游代码】，是为 H3C MegaBook 14 调试新增的。
 *
 * 与上游的差异：
 *   - 上游只用 pr_info/pr_err 打到内核日志，必须接 adb/dmesg 才能看；
 *     没有 adb 也能在 Windows 侧裸读，崩溃/重启都不丢；
 *   - 每行加 [秒.毫秒] 时间戳（上游没有），用于对齐崩溃前最后一条日志；
 *   - 【只保留 persistent 一个通道】：
 *       /sdcard/ksu-boot.log          从内核写不稳定，已移除；
 *       /data/local/tmp/ksu-boot.log  依赖 adb，已移除；
 *     因此不再有"通道探测/状态行"逻辑，第一条日志直接从 512KB 开始写。
 *
 *       严禁在原子上下文（tracepoint / kprobe / spinlock / irq）中调用，
 *       那种场景只能用 pr_info()。
 *
 *   编译期开关：KSU_X86_PERSISTENT_BOOT_LOG
 *       定义   -> 启用 persistent 日志（build-megaos-x64.sh 默认）
 *       未定义 -> ksu_blog() 为 no-op（build-megaos-x64.sh --no-persist-log）
 * ========================================================================== */
#include "klog.h"

/* [KSU-X86-PORT] 避免在 core/init.c 里包含 shim 头（包含顺序会与 mm_types 冲突） */
void ksu_shim_ensure_all_endbr(void);
void ksu_panic_dumper_early_init(void);
void ksu_shim_data_retry(const char *name);

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#ifdef KSU_X86_PERSISTENT_BOOT_LOG
/* persistent 分区（1MB）：日志从 512KB 起顺序追加；
 * 静态变量每次开机归零 ⇒ 每次开机从头重写。 */
static struct file *ksu_blog_f;
static loff_t ksu_blog_persist_off;

/* [KSU-X86-PORT] 只在开机早期打开一次并长期持有 fd。
 * 之前每次 ksu_blog 都 filp_open，等 SELinux policy 生效后就打不开了；
 * 而 panic dumper 的 fd 是早期打开的，所以只有它能写进去。 */
static struct file *ksu_persistent_open_retry(void)
{
	struct file *f;
	int i;

	for (i = 0; i < 50; i++) {
		f = filp_open("/dev/block/by-name/persistent", O_WRONLY | O_SYNC, 0);
		if (!IS_ERR(f))
			return f;
		msleep(100);
	}
	return NULL;
}

void ksu_blog_early_init(void)
{
	if (!ksu_blog_f)
		ksu_blog_f = ksu_persistent_open_retry();
}

static void ksu_blog_to_persist(const char *buf, int n)
{
	if (!ksu_blog_f)
		return;
	if (ksu_blog_persist_off == 0)
		ksu_blog_persist_off = 512 * 1024;
	ksu_blog_f->f_pos = ksu_blog_persist_off;
	if (kernel_write(ksu_blog_f, buf, n, &ksu_blog_f->f_pos) == n)
		ksu_blog_persist_off += n;
}

void ksu_blog(const char *fmt, ...)
{
	char buf[320];
	struct timespec64 ts;
	va_list ap;
	int n, m;

	/* [KSU-X86-PORT] 时间戳前缀 */
	ktime_get_boottime_ts64(&ts);
	n = snprintf(buf, sizeof(buf), "[%5lld.%03ld] ", (long long)ts.tv_sec,
		     ts.tv_nsec / 1000000);
	if (n < 0)
		n = 0;
	va_start(ap, fmt);
	m = vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);
	if (m <= 0)
		return;
	n += m;
	if (n > (int)sizeof(buf) - 1)
		n = sizeof(buf) - 1;

	ksu_blog_to_persist(buf, n);
}
#else
void ksu_blog_early_init(void)
{
}
#endif /* KSU_X86_PERSISTENT_BOOT_LOG */

/* ============================================================================
 * [KSU-X86-PORT] 调试日志系统到此结束。
 * 以下恢复为 KernelSU 上游代码（未改动）。
 * ========================================================================== */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "feature/module_blacklist.h"
#include "feature/shell_su_adb_only.h"
#include "infra/symbol_resolver.h"

#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void  ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int  kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

#ifdef MODULE
bool ksu_bundled = false;
module_param_named(bundled, ksu_bundled, bool, 0);
#endif

/* [KSU-X86-PORT] 事件驱动，不做定时轮询，也不挂 kretprobe：
 *   - module_init 末尾先 schedule 一次（晚加载时 policy 已就绪）；
 *   - 第一次 setresuid（zygote/manager）和 sucompat 命中时 kick；
 *   - 这两个事件都发生在 policy 加载之后，work 里再解析 selinux_state。
 * 没有 return trampoline，不会因为 BOLT/LTO 的函数拆分炸返回地址。 */
static struct work_struct ksu_sepolicy_work;

static void ksu_sepolicy_work_fn(struct work_struct *w)
{
    (void)w;

    ksu_shim_data_retry("selinux_state");
    cache_sid();

    if (ksu_su_domain_ready()) {
        setup_ksu_cred();
        pr_info("kernelsu: sepolicy event: su domain already ready\n");
        ksu_blog("sepolicy event: ready\n");
        return;
    }

    ksu_reset_rules_applied();
    apply_kernelsu_rules();
    cache_sid();

    if (ksu_su_domain_ready()) {
        setup_ksu_cred();
        pr_info("kernelsu: sepolicy event: rules applied\n");
        ksu_blog("sepolicy event: applied\n");
    } else {
        pr_err("kernelsu: sepolicy event: apply failed\n");
        ksu_blog("sepolicy event: failed\n");
    }
}

static void ksu_sepolicy_event_init(void)
{
    INIT_WORK(&ksu_sepolicy_work, ksu_sepolicy_work_fn);
}

void ksu_sepolicy_kick(void)
{
    if (ksu_su_domain_ready())
        return;
    schedule_work(&ksu_sepolicy_work);
}


int  kernelsu_init(void)
{
    pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

    /* [KSU-X86-PORT] 先初始化 policy 事件 work，再继续 init。 */
    ksu_sepolicy_event_init();

    /* [KSU-X86-PORT] 先拿到 persistent fd，再装 hook / 做慢速 ENDBR 补丁。
     * 这两个 fd 必须在 SELinux policy 生效前打开，否则后续写日志会被拦。 */
    ksu_blog_early_init();
    ksu_panic_dumper_early_init();

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

    ksu_init_symbol_resolver();
    ksu_syscall_hook_init();

    /* [KSU-X86-PORT] 在 IRQ 开启的 init 阶段补好所有 shim 目标的 ENDBR。
     * 不能等第一次调用（change_pid 会在 tasklist_lock 下被调用）。 */
    ksu_shim_ensure_all_endbr();

    // Block modules early, before vendor modules are loaded in second stage.
    ksu_module_blacklist_init();

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
    ksu_selinux_hide_init();
    ksu_shell_su_adb_only_init();

    ksu_supercalls_init();
    ksu_app_profile_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_syscall_hook_manager_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        ksu_feature_apply_forced();

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();


        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif

    return 0;
}

void __exit kernelsu_exit(void)
{
    cancel_work_sync(&ksu_sepolicy_work);

    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_shell_su_adb_only_exit();
    ksu_selinux_hide_exit();
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();
    ksu_module_blacklist_exit();

    put_cred(ksu_cred);
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
/* [KSU-X86-PORT] 与上游一致：模块装载时立即 init（不延迟）。
 * hook 必须在 zygote/app 启动前就绪，否则管理器的 setresuid 注入会被错过。
 * /data 相关（allowlist、throne/crown）由 ksud 的 post-fs-data 与
 * pkg_observer（packages.list fsnotify）在 /data 就绪后完成。 */
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

