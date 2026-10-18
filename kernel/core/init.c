
/* ================= KSU_X86_BOOT_LOG =================
 * 双通道落盘日志：/data/local/tmp/ksu-boot.log + persistent@512KB
 * 全部 O_SYNC，保证崩溃/重启也不丢；日志最后一行 = 崩溃点。
 * ================================================== */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

static loff_t ksu_blog_persist_pos = 512 * 1024;

static bool ksu_blog_first = true;
static char ksu_blog_status[160];


static loff_t ksu_blog_persist_off;

/* persistent：从 512KB 起【顺序追加】；每次开机 statics 归零 ⇒ 每次开机从头重写 ✓
 * 直接读裸设备 + O_SYNC ⇒ 崩溃/重启都不丢 ✓ */
static void ksu_blog_to_persist(const char *buf, int n)
{
	struct file *f = filp_open("/dev/block/by-name/persistent", O_WRONLY | O_SYNC, 0);

	if (IS_ERR(f))
		return;
	if (ksu_blog_persist_off == 0)
		ksu_blog_persist_off = 512 * 1024;
	f->f_pos = ksu_blog_persist_off;
	if (kernel_write(f, buf, n, &f->f_pos) == n)
		ksu_blog_persist_off += n;
	filp_close(f, NULL);
}

static void ksu_blog_to_file(const char *path, const char *buf, int n, const char *tag)
{
	struct file *f = filp_open(path, O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);

	if (IS_ERR(f)) {
		if (ksu_blog_first) {
			strlcat(ksu_blog_status, tag, sizeof(ksu_blog_status));
			strlcat(ksu_blog_status, "=ERR ", sizeof(ksu_blog_status));
		}
		return;
	}
	kernel_write(f, buf, n, &f->f_pos);
	filp_close(f, NULL);
	if (ksu_blog_first) {
		strlcat(ksu_blog_status, tag, sizeof(ksu_blog_status));
		strlcat(ksu_blog_status, "=ok ", sizeof(ksu_blog_status));
	}
}

void ksu_blog(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if (n > (int)sizeof(buf) - 1)
		n = sizeof(buf) - 1;

	ksu_blog_to_file("/sdcard/ksu-boot.log", buf, n, "sdcard");
	ksu_blog_to_file("/data/local/tmp/ksu-boot.log", buf, n, "data");
	ksu_blog_to_persist(buf, n);

	if (ksu_blog_first) {
		char st[200];
		int m;
		struct file *f;

		ksu_blog_first = false;
		m = snprintf(st, sizeof(st), "[ksu-blog channels] %s\n", ksu_blog_status);
		if (m > 0) {
			ksu_blog_to_file("/sdcard/ksu-boot.log", st, m, "x");
			ksu_blog_to_file("/data/local/tmp/ksu-boot.log", st, m, "x");
		}
		/* persistent 需要定位到 512KB */
		f = filp_open("/dev/block/by-name/persistent", O_WRONLY | O_SYNC, 0);
		if (!IS_ERR(f)) {
			f->f_pos = 512 * 1024;
			kernel_write(f, st, m, &f->f_pos);
			filp_close(f, NULL);
		}
	}
}

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


#ifdef KSU_X86_BAIL_AT
#define KSU_BAIL(n) do { if (KSU_X86_BAIL_AT <= (n)) { pr_info("ksu-shim: BAIL@%d\n", (n)); return 0; } } while (0)
#else
#define KSU_BAIL(n) do { } while (0)
#endif

int  kernelsu_init(void)
{
    KSU_BAIL(1);
    pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
#ifndef KSU_X86_SKIP_INDIRECT_SAFE_CHECK
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
#endif /* !KSU_X86_SKIP_INDIRECT_SAFE_CHECK */
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

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

    ksu_blog("STEP: 1 prepare_creds\n");
    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

    KSU_BAIL(2);
    ksu_blog("STEP: 2 init_symbol_resolver(SKIPPED)\n");
    ksu_init_symbol_resolver();
    KSU_BAIL(3);
    ksu_blog("STEP: 3 syscall_hook_init\n");
    ksu_syscall_hook_init();

    KSU_BAIL(4);
    // Block modules early, before vendor modules are loaded in second stage.
    ksu_blog("STEP: 4 module_blacklist_init\n");
    ksu_module_blacklist_init();

    KSU_BAIL(5);
    ksu_blog("STEP: 5 feature_init\n");
    ksu_feature_init();
    ksu_blog("STEP: 6 sulog_init\n");
    ksu_sulog_init();
    ksu_blog("STEP: 7 adb_root_init\n");
    ksu_adb_root_init();
    ksu_blog("STEP: 8 lsm_hook_init\n");
    ksu_lsm_hook_init();
    ksu_blog("STEP: 9 selinux_hide_init\n");
    ksu_selinux_hide_init();
    ksu_blog("STEP: 10 shell_su_adb_only_init\n");
    ksu_shell_su_adb_only_init();

    KSU_BAIL(6);
    ksu_blog("STEP: 11 supercalls_init\n");
    ksu_supercalls_init();
    ksu_blog("STEP: 12 app_profile_init\n");
    ksu_app_profile_init();

    KSU_BAIL(7);
    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

    ksu_blog("STEP: 14 allowlist_init\n");
        ksu_allowlist_init();
        ksu_load_allow_list();

    ksu_blog("STEP: 13 syscall_hook_manager_init(late)\n");
#ifndef KSU_X86_SKIP_HOOK_MANAGER
        ksu_syscall_hook_manager_init();
#else
        ksu_blog("STEP 13 syscall_hook_manager_init SKIPPED\n");
#endif

    ksu_blog("STEP: 15 throne_tracker_init\n");
        ksu_throne_tracker_init();
        ksu_observer_init();
    ksu_blog("STEP: 17 file_wrapper_init\n");
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

    ksu_blog("STEP: 16 ksud_init\n");
        ksu_ksud_init();    KSU_BAIL(8);


        ksu_file_wrapper_init();
    }

    KSU_BAIL(9);
#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
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

/* ------------------------------------------------------------------
 * 延迟初始化：模块装载时只调度一个 workqueue，15 秒后再做真正的 init。
 * 原因：那些炸点（stop_machine / set_memory_rw 改 .rodata / 14 字节文本覆盖）
 *       都发生在"系统最早、什么都还没就绪"的时刻；推迟到系统起来之后既安全，
 *       又让我们能把每一步日志写进 /data/local/tmp（方便定位）。
 * ------------------------------------------------------------------ */
static void ksu_deferred_init_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_deferred_init_work, ksu_deferred_init_fn);

static int ksu_boot_stub(void)
{
    pr_info("ksu-shim: deferring kernelsu_init by 15s (workqueue)\n");
    schedule_delayed_work(&ksu_deferred_init_work, 15 * HZ);
    return 0;
}

static void ksu_deferred_init_fn(struct work_struct *w)
{
    ksu_blog("=== deferred init BEGIN ===\n");
    pr_info("ksu-shim: deferred kernelsu_init begins\n");
    kernelsu_init();
    ksu_blog("=== deferred init RETURNED (no crash) ===\n");
    pr_info("ksu-shim: deferred kernelsu_init done\n");
}

module_init(ksu_boot_stub);

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
