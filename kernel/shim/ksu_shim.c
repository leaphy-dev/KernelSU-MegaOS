// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU LKM 救援层（x86_64 / non-GKI）
 *
 * 背景：
 *   本设备内核（6.12.30-ga86c39fcddce，non-GKI）没有导出 KernelSU 需要的
 *   ~58 个符号，因此官方 LKM 无法加载。本文件不修改 KernelSU 的任何逻辑，
 *   只做一件事：在模块内用【同名定义】满足这些引用，真实地址改为运行时解析。
 *
 *   ① 引导：用 kprobe 技巧拿到 kallsyms_lookup_name 的真实地址
 *           （register_kprobe 是本设备【已导出】的符号）
 *   ② 函数：同名 wrapper，内部转发到解析出的函数指针
 *   ③ 数据：见 ksu_shim_data_addr()（本设备 KALLSYMS_ALL=n，数据符号不在
 *           kallsyms 里，需靠 _stext 偏移表，见 ksu_data_syms[]）
 *
 * 所有壳在解析失败时都【安全返回/使用哑对象】，绝不空指针解引用。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/user.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/seccomp.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/proc_ns.h>
#include <linux/lsm_hooks.h>
#include <linux/mm_types.h>
#include <linux/utsname.h>
#include <asm/fixmap.h>
#include <asm/ptrace.h>
#include <linux/syscalls.h>

/* SELinux 内部头（Kbuild 已加 -I security/selinux -I security/selinux/include） */
#include "ss/avtab.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/policydb.h"
#include "ss/sidtab.h"
#include "ss/symtab.h"
#include "ss/mls.h"
#include "ss/conditional.h"
#include "ss/services.h"
#include "avc.h"
#include "objsec.h"
#include "security.h"

#include "infra/symbol_resolver.h"

/* fs/internal.h 不在 include 路径里，path_mount/path_umount 自己声明 */
extern int path_mount(const char *dev_name, struct path *path, const char *type_page,
		      unsigned long flags, void *data_page);
extern int path_umount(struct path *path, int flags);
extern void ext4_unregister_sysfs(struct super_block *sb);

/* ==================================================================
 * ① 引导
 * ================================================================== */

typedef unsigned long (*ksu_kln_t)(const char *);
typedef int (*ksu_koes_t)(int (*fn)(void *, const char *, unsigned long), void *data);
typedef const char *(*ksu_kl_t)(unsigned long, unsigned long *, unsigned long *, char **, char *);
typedef int (*ksu_klso_t)(unsigned long, unsigned long *, unsigned long *);

static unsigned long ksu_bootstrap(const char *name)
{
	struct kprobe kp;
	unsigned long addr = 0;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = name;
	if (register_kprobe(&kp) == 0) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
}

unsigned long kallsyms_lookup_name(const char *name)
{
	static ksu_kln_t fn;

	if (unlikely(!fn)) {
		fn = (ksu_kln_t)ksu_bootstrap("kallsyms_lookup_name");
		if (!fn) {
			pr_err("ksu-shim: 引导 kallsyms_lookup_name 失败\n");
			return 0;
		}
		pr_info("ksu-shim: 引导成功 kallsyms_lookup_name\n");
	}
	return fn(name);
}

int kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
				unsigned long *offset)
{
	static ksu_klso_t fn;

	if (unlikely(!fn))
		fn = (ksu_klso_t)kallsyms_lookup_name("kallsyms_lookup_size_offset");
	if (unlikely(!fn))
		return 0;
	return fn(addr, symbolsize, offset);
}

const char *kallsyms_lookup(unsigned long addr, unsigned long *symbolsize,
			    unsigned long *offset, char **modname, char *namebuf)
{
	static ksu_kl_t fn;

	if (unlikely(!fn))
		fn = (ksu_kl_t)kallsyms_lookup_name("kallsyms_lookup");
	if (unlikely(!fn))
		return NULL;
	return fn(addr, symbolsize, offset, modname, namebuf);
}

int kallsyms_on_each_symbol(int (*cb)(void *, const char *, unsigned long), void *data)
{
	static ksu_koes_t fn;

	if (unlikely(!fn))
		fn = (ksu_koes_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	if (unlikely(!fn))
		return -ENOENT;
	return fn(cb, data);
}

/* ==================================================================
 * ② 函数壳
 *    注意：本设备内核 kallsyms 只含文本符号（KALLSYMS_ALL=n），
 *    所以这些【函数】都能被解析到；数据对象走 ③。
 * ================================================================== */

#define SHIM_FN(ret, name, proto, call, notfound)                            \
	ret name proto                                                       \
	{                                                                    \
		static ret(*fn) proto;                                       \
		if (unlikely(!fn)) {                                         \
			fn = (ret(*) proto)                                  \
				ksu_resolve_symbol_for_functable_hook(#name);\
			if (unlikely(!fn)) {                                 \
				pr_warn_once("ksu-shim: 未能解析 %s\n", #name);\
				return notfound;                             \
			}                                                    \
		}                                                            \
		return fn call;                                              \
	}

#define SHIM_FN_V(name, proto, call)                 \
	void name proto                              \
	{                                            \
		static void (*fn) proto;             \
		if (unlikely(!fn)) {                 \
			fn = (void (*)proto)         \
				ksu_resolve_symbol_for_functable_hook(#name);\
			if (unlikely(!fn)) {         \
				pr_warn_once("ksu-shim: 未能解析 %s\n", #name);\
				return;              \
			}                            \
		}                                    \
		fn call;                             \
	}

/* --- 通用 --- */
SHIM_FN(struct user_struct *, alloc_uid, (kuid_t uid), (uid), NULL)
SHIM_FN_V(change_pid, (struct task_struct *task, enum pid_type type, struct pid *pid), (task, type, pid))
SHIM_FN(bool, current_is_single_threaded, (void), (), false)
SHIM_FN(long, copy_to_kernel_nofault, (void *dst, const void *src, size_t size), (dst, src, size), -EFAULT)
SHIM_FN(long, strncpy_from_user_nofault, (char *dst, const void __user *unsafe_addr, long count), (dst, unsafe_addr, count), -EFAULT)
SHIM_FN_V(native_set_fixmap, (unsigned idx, phys_addr_t phys, pgprot_t flags), (idx, phys, flags))
SHIM_FN(int, ksys_unshare, (unsigned long unshare_flags), (unshare_flags), -ENOSYS)
SHIM_FN(int, set_cred_ucounts, (struct cred *new), (new), -EINVAL)
SHIM_FN_V(set_fs_pwd, (struct fs_struct *fs, const struct path *path), (fs, path))
SHIM_FN_V(seccomp_filter_release, (struct task_struct *tsk), (tsk))
SHIM_FN(int, ns_get_path, (struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops), (path, task, ns_ops), -ENOSYS)
SHIM_FN(int, path_mount, (const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page), (dev_name, path, type_page, flags, data_page), -ENOSYS)
SHIM_FN(int, path_umount, (struct path *path, int flags), (path, flags), -ENOSYS)
SHIM_FN_V(ext4_unregister_sysfs, (struct super_block *sb), (sb))
SHIM_FN(asmlinkage long, __x64_sys_close, (const struct pt_regs *regs), (regs), -ENOSYS)
SHIM_FN(asmlinkage long, __x64_sys_setns, (const struct pt_regs *regs), (regs), -ENOSYS)

/* --- SELinux --- */
SHIM_FN(int, avc_has_perm, (u32 ssid, u32 tsid, u16 tclass, u32 requested, struct common_audit_data *auditdata), (ssid, tsid, tclass, requested, auditdata), -EACCES)
SHIM_FN(int, avc_ss_reset, (u32 seqno), (seqno), -EINVAL)
SHIM_FN(int, avtab_alloc, (struct avtab *h, u32 nrules), (h, nrules), -ENOMEM)
SHIM_FN_V(avtab_destroy, (struct avtab *h), (h))
SHIM_FN(struct avtab_node *, avtab_insert_nonunique, (struct avtab *h, const struct avtab_key *key, const struct avtab_datum *datum), (h, key, datum), NULL)
SHIM_FN(struct avtab_node *, avtab_search_node, (struct avtab *h, const struct avtab_key *key), (h, key), NULL)
SHIM_FN(struct avtab_node *, avtab_search_node_next, (struct avtab_node *node, u16 specified), (node, specified), NULL)
SHIM_FN_V(cond_compute_av, (struct avtab *ctab, struct avtab_key *key, struct av_decision *avd, struct extended_perms *xperms), (ctab, key, avd, xperms))
SHIM_FN(int, ebitmap_cmp, (const struct ebitmap *e1, const struct ebitmap *e2), (e1, e2), 0)
SHIM_FN(int, ebitmap_contains, (const struct ebitmap *e1, const struct ebitmap *e2, u32 last_e2bit), (e1, e2, last_e2bit), 0)
SHIM_FN_V(ebitmap_destroy, (struct ebitmap *e), (e))
SHIM_FN(int, ebitmap_get_bit, (const struct ebitmap *e, u32 bit), (e, bit), 0)
SHIM_FN(int, ebitmap_set_bit, (struct ebitmap *e, u32 bit, int value), (e, bit, value), 0)
SHIM_FN(int, __hashtab_insert, (struct hashtab *h, struct hashtab_node **dst, void *key, void *datum), (h, dst, key, datum), -ENOMEM)
SHIM_FN(int, mls_compute_context_len, (struct policydb *p, struct context *context), (p, context), 0)
SHIM_FN(int, mls_context_to_sid, (struct policydb *p, char oldc, char *scontext, struct context *context, struct sidtab *s, u32 def_sid), (p, oldc, scontext, context, s, def_sid), -EINVAL)
SHIM_FN_V(mls_sid_to_context, (struct policydb *p, struct context *context, char **scontext), (p, context, scontext))
SHIM_FN(int, policydb_context_isvalid, (struct policydb *p, struct context *c), (p, c), 0)
SHIM_FN_V(policydb_destroy, (struct policydb *p), (p))
SHIM_FN(struct filename_trans_datum *, policydb_filenametr_search, (struct policydb *p, struct filename_trans_key *key), (p, key), NULL)
SHIM_FN(int, policydb_load_isids, (struct policydb *p, struct sidtab *s), (p, s), -EINVAL)
SHIM_FN(int, policydb_read, (struct policydb *p, void *fp), (p, fp), -EINVAL)
SHIM_FN(int, policydb_write, (struct policydb *p, void *fp), (p, fp), -EINVAL)
SHIM_FN(int, security_bounded_transition, (u32 oldsid, u32 newsid), (oldsid, newsid), -EINVAL)
SHIM_FN_V(selinux_status_update_policyload, (u32 seqno), (seqno))
SHIM_FN_V(selnl_notify_policyload, (u32 seqno), (seqno))
SHIM_FN(int, sidtab_context_to_sid, (struct sidtab *s, struct context *context, u32 *sid), (s, context, sid), -EINVAL)
SHIM_FN_V(sidtab_destroy, (struct sidtab *s), (s))
SHIM_FN(struct sidtab_entry *, sidtab_search_entry, (struct sidtab *s, u32 sid), (s, sid), NULL)
SHIM_FN(int, sidtab_sid2str_get, (struct sidtab *s, struct sidtab_entry *entry, char **out, u32 *out_len), (s, entry, out, out_len), -EINVAL)
SHIM_FN_V(sidtab_sid2str_put, (struct sidtab *s, struct sidtab_entry *entry, const char *str, u32 str_len), (s, entry, str, str_len))
SHIM_FN(int, symtab_insert, (struct symtab *s, char *name, void *datum), (s, name, datum), -ENOMEM)
SHIM_FN(void *, symtab_search, (struct symtab *s, const char *name), (s, name), NULL)

/* ==================================================================
 * ③ 数据对象
 *    本设备 KALLSYMS_ALL=n → 数据符号不在 kallsyms 里。
 *    先用 kallsyms 试（若将来开了 KALLSYMS_ALL 就直接成功），
 *    否则查 _stext 偏移表（offs 为 0 = 尚未确定，届时使用哑对象，不崩溃）。
 * ================================================================== */

struct ksu_data_sym {
	const char *name;
	unsigned long off; /* 相对 _stext 的偏移；0 = 未确定 */
};

static const struct ksu_data_sym ksu_data_syms[] = {
	{ "init_mm",               0 },
	{ "selinux_state",         0 },
	{ "selinux_blob_sizes",    0 },
	{ "mntns_operations",      0 },
	{ "__tracepoint_sys_enter",0 },
};

unsigned long ksu_shim_data_addr(const char *name)
{
	unsigned long addr = find_kernel_symbol_exact(name);
	unsigned long stext;
	int i;

	if (addr)
		return addr;

	stext = kallsyms_lookup_name("_stext");
	for (i = 0; i < ARRAY_SIZE(ksu_data_syms); i++) {
		if (strcmp(ksu_data_syms[i].name, name) != 0)
			continue;
		if (!ksu_data_syms[i].off) {
			pr_warn_once("ksu-shim: 数据符号 %s 尚无偏移（使用哑对象）\n", name);
			return 0;
		}
		return stext + ksu_data_syms[i].off;
	}
	pr_warn_once("ksu-shim: 未知数据符号 %s\n", name);
	return 0;
}

/* 哑对象：确保解析失败时不会空指针解引用 */
struct selinux_state ksu_dummy_selinux_state;
struct lsm_blob_sizes ksu_dummy_selinux_blob_sizes;
struct mm_struct ksu_dummy_init_mm;
const struct proc_ns_operations ksu_dummy_mntns_operations;

void *ksu_shim_data_or_dummy(const char *name, void *dummy)
{
	unsigned long a = ksu_shim_data_addr(name);

	return a ? (void *)a : dummy;
}

/* ---- __tracepoint_sys_enter ----
 * 它是被 <trace/events/syscalls.h> 里的宏在【头文件内】引用的，无法用 #define 替换，
 * 因此这里先定义一个模块内对象让链接通过；Phase 2 会改 hook/syscall_hook_manager.c
 * 直接把真地址喂给 tracepoint_probe_register_prio()。
 */
struct tracepoint __tracepoint_sys_enter;

/* ---- selinux_blob_sizes ----
 * 它被 <security/selinux/include/objsec.h> 里的【内联函数】(selinux_cred 等) 引用，
 * #define 无法作用到已解析的内联体，因此这里定义模块内的真对象；
 * Phase 2 会把内核里的真实数值 memcpy 进来（blob 尺寸在初始化后不再变化，拷贝等价）。
 */
struct lsm_blob_sizes selinux_blob_sizes;

void ksu_shim_fill_selinux_blob_sizes(void)
{
	unsigned long real = ksu_shim_data_addr("selinux_blob_sizes");

	if (real && (void *)real != (void *)&selinux_blob_sizes)
		memcpy(&selinux_blob_sizes, (void *)real, sizeof(selinux_blob_sizes));
}
