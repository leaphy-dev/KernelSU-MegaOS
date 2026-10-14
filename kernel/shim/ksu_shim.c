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
#include <linux/mm.h>
#include <linux/gfp.h>
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

/* 注意：本文件【不能】include shim/ksu_shim.h —— 那里的宏会把本文件的
 *      struct 声明（如 struct selinux_state s）也替换掉。这里用显式原型。 */
unsigned long ksu_shim_data_addr(const char *name);
void *ksu_shim_data_or_dummy(const char *name, void *dummy);
bool ksu_shim_resolved(const char *name);


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
 * ③ 数据对象：运行时解析
 *
 * 本设备 CONFIG_KALLSYMS_ALL=n → 数据符号【不在 kallsyms 里】，必须另想办法：
 *   A) 引用反查：从"已知函数"的机器码里抠出 RIP 相对引用的目标
 *      （离线已在我们自己的 vmlinux 上确认了哪些非 __init 函数引用了哪个符号、
 *        访问的是哪个字段）
 *   B) 结构模式扫描：tracepoint 指针表 / proc_ns_operations 的 name 字段
 *
 * 所有内存读取都走 copy_from_kernel_nofault()，坏指针只会返回错误、不会 oops。
 * 每个符号解析后都做【语义自检】，结果写日志，便于在设备上核对。
 * ================================================================== */

static inline bool ksu_is_kptr(unsigned long v)
{
	return v >= 0xffffffff80000000UL && v != ~0UL;
}

static long ksu_safe_read(void *dst, const void *src, size_t n)
{
	static long (*fn)(void *, const void *, size_t);

	if (unlikely(!fn)) {
		fn = (long (*)(void *, const void *, size_t))
			kallsyms_lookup_name("copy_from_kernel_nofault");
		if (!fn)
			return -ENOENT;
	}
	return fn(dst, src, n);
}

static bool ksu_str_eq(unsigned long p, const char *want)
{
	char buf[16];
	size_t n = strlen(want) + 1;

	if (!ksu_is_kptr(p) || n > sizeof(buf))
		return false;
	if (ksu_safe_read(buf, (const void *)p, n) < 0)
		return false;
	return memcmp(buf, want, n) == 0;
}

static bool ksu_is_text(unsigned long v)
{
	static unsigned long lo, hi;

	if (unlikely(!lo)) {
		lo = kallsyms_lookup_name("_stext");
		hi = kallsyms_lookup_name("_etext");
		if (!lo || !hi || hi <= lo)
			lo = 0xffffffff81000000UL, hi = 0xffffffff90000000UL;
	}
	return v >= lo && v < hi;
}

/* 扫描函数机器码里所有 RIP 相对引用的目标地址
 * 支持的编码形态（覆盖我们离线确认过的所有引用点）：
 *   无 REX            : 8b/8d/89/8a/88/8c/03/2b/39/3b/84/85/c7   disp32
 *   REX (0x40-0x4f)   : 同上
 *   两字节 opcode     : 0f b6/b7/be/bf                           disp32
 * 指令长度：disp32 在末尾，故 len = 前缀 + opcode + modrm + 4
 */
#define KSU_MAX_REFS 64

static bool ksu_has_rip_modrm(const u8 *q, unsigned long len)
{
	return (q[len - 5] & 0xc7) == 0x05;      /* mod=00, rm=101 */
}

static int ksu_scan_rip_refs(unsigned long faddr, unsigned long fsize,
			     unsigned long *out, int max)
{
	const u8 *p = (const u8 *)faddr;
	int n = 0;
	unsigned long i;

	if (!ksu_is_kptr(faddr) || !fsize || fsize > 0x100000)
		return 0;

	for (i = 0; i + 6 <= fsize && n < max; i++) {
		const u8 *q = p + i;
		unsigned long len = 0, k = 0;
		u8 op;

		if (q[0] >= 0x40 && q[0] <= 0x4f)       /* 可选 REX 前缀 */
			k = 1;
		if (i + k + 2 > fsize)
			break;
		op = q[k];

		if (op == 0x0f) {                        /* 两字节 opcode */
			u8 op2 = q[k + 1];
			if (!(op2 == 0xb6 || op2 == 0xb7 || op2 == 0xbe || op2 == 0xbf))
				continue;
			len = k + 7;
		} else if (op == 0x8b || op == 0x8d || op == 0x89 || op == 0x8a ||
			   op == 0x88 || op == 0x8c || op == 0x03 || op == 0x2b ||
			   op == 0x39 || op == 0x3b || op == 0x84 || op == 0x85 ||
			   op == 0xc7) {
			len = k + 6;
		} else {
			continue;
		}

		if (i + len > fsize)
			break;
		if (!ksu_has_rip_modrm(q, len))
			continue;

		{
			/* disp32 贴着操作数末尾（对 0f b6 也成立：modrm 后就 disp32） */
			const u8 *d = q + (op == 0x0f ? (k + 3) : (k + 2));
			s32 disp = (s32)((u32)d[0] | ((u32)d[1] << 8) |
					 ((u32)d[2] << 16) | ((u32)d[3] << 24));
			unsigned long t = (unsigned long)(q + len) + (long)disp;

			if (ksu_is_kptr(t))
				out[n++] = t;
		}
	}
	return n;
}

static int ksu_refs_of(const char *fname, unsigned long *out, int max)
{
	unsigned long a = kallsyms_lookup_name(fname), sz = 0, off = 0;

	if (!a)
		return 0;
	if (!kallsyms_lookup_size_offset(a, &sz, &off) || sz == 0 || sz > 0x40000)
		sz = 0x800;                              /* 拿不到大小就只扫函数头 */
	return ksu_scan_rip_refs(a, sz, out, max);
}

/* ---------------- init_mm ---------------- */
static bool ksu_valid_init_mm(unsigned long cand)
{
	unsigned long a = (unsigned long)&ksu_valid_init_mm;
	unsigned long pgd_p;
	pgd_t pgd;

	if (!ksu_is_kptr(cand))
		return false;
	/* 全部用安全读，坏指针只返回错误，不会 oops */
	if (ksu_safe_read(&pgd_p, (const void *)(cand + offsetof(struct mm_struct, pgd)), 8) < 0)
		return false;
	if (!ksu_is_kptr(pgd_p))
		return false;
	if (ksu_safe_read(&pgd, (const void *)(pgd_p + pgd_index(a) * sizeof(pgd_t)),
			  sizeof(pgd)) < 0)
		return false;
	return !pgd_none(pgd) && !pgd_bad(pgd);
}

static unsigned long ksu_resolve_init_mm(void)
{
	static const char *cands[] = {
		"lookup_address", "slow_virt_to_phys", "vmalloc_to_page",
		"set_pte_vaddr", "drain_mmlist", "__get_user_pages",
	};
	unsigned long refs[KSU_MAX_REFS];
	int i, k, n;

	for (i = 0; i < ARRAY_SIZE(cands); i++) {
		n = ksu_refs_of(cands[i], refs, KSU_MAX_REFS);
		for (k = 0; k < n; k++) {
			unsigned long base =
				refs[k] - offsetof(struct mm_struct, pgd);
			if (ksu_valid_init_mm(base))
				return base;
		}
	}
	return 0;
}

/* ---------------- selinux_state ---------------- */
static bool ksu_valid_selinux_state(unsigned long cand)
{
	struct selinux_state s;

	if (!ksu_is_kptr(cand))
		return false;
	if (ksu_safe_read(&s, (const void *)cand, sizeof(s)) < 0)
		return false;
	if (s.initialized != true || s.enforcing > 1)
		return false;
	if (!ksu_is_kptr((unsigned long)s.policy))
		return false;
	return true;
}

static unsigned long ksu_resolve_selinux_state(void)
{
	static const char *cands[] = { "avc_denied", "sel_read_enforce", "selinux_add_opt" };
	unsigned long refs[KSU_MAX_REFS];
	int i, k, n;

	for (i = 0; i < ARRAY_SIZE(cands); i++) {
		n = ksu_refs_of(cands[i], refs, KSU_MAX_REFS);
		for (k = 0; k < n; k++)
			if (ksu_valid_selinux_state(refs[k]))
				return refs[k];
	}
	return 0;
}

/* ---------------- selinux_blob_sizes -----------------
 * 它被 objsec.h 的内联函数引用，因此模块里已有同名【真对象】，
 * 这里找到内核里的真值后【拷贝】进来即可（blob 尺寸初始化后不再变）。
 */
static bool ksu_valid_blob_sizes(unsigned long cand)
{
	int v[14];
	int i, ok = 0;

	if (!ksu_is_kptr(cand))
		return false;
	if (ksu_safe_read(v, (const void *)cand, sizeof(v)) < 0)
		return false;
	for (i = 0; i < 14; i++) {
		if (v[i] < 0 || v[i] > 0x100000)
			return false;
		if (v[i])
			ok++;
	}
	return ok >= 1;
}

static unsigned long ksu_resolve_blob_sizes(void)
{
	static const char *cands[] = { "selinux_syslog", "selinux_capset", "selinux_bpf",
				       "sel_write_bool", "sel_write_load", "selinux_bpf_map" };
	unsigned long refs[KSU_MAX_REFS];
	int i, k, n;

	for (i = 0; i < ARRAY_SIZE(cands); i++) {
		n = ksu_refs_of(cands[i], refs, KSU_MAX_REFS);
		for (k = 0; k < n; k++)
			if (ksu_valid_blob_sizes(refs[k]))
				return refs[k];
	}
	return 0;
}

/* ---------------- mntns_operations ----------------
 * 文本段里没有任何直接引用（只被数据数组引用），因此扫描 .rodata：
 * 找 {name, real_ns_name, type, get, put, install, ...} 中 name=="mnt" 的那一个。
 */
static unsigned long ksu_resolve_mntns_operations(void)
{
	unsigned long lo = kallsyms_lookup_name("__start_rodata");
	unsigned long hi = kallsyms_lookup_name("__start_ro_after_init");
	unsigned long a, name, real, get, put, install;

	if (!lo || !hi || hi <= lo || (hi - lo) > 0x4000000UL)
		return 0;
	lo = (lo + 7) & ~7UL;

	for (a = lo; a + 64 <= hi; a += 8) {
		if (ksu_safe_read(&name, (const void *)a, 8) < 0)
			break;
		if (!ksu_str_eq(name, "mnt"))
			continue;
		if (ksu_safe_read(&real, (const void *)(a + 8), 8) < 0)
			continue;
		if (!ksu_str_eq(real, "mnt"))
			continue;
		if (ksu_safe_read(&get, (const void *)(a + 24), 8) < 0 ||
		    ksu_safe_read(&put, (const void *)(a + 32), 8) < 0 ||
		    ksu_safe_read(&install, (const void *)(a + 40), 8) < 0)
			continue;
		if (!ksu_is_text(get) || !ksu_is_text(put) || !ksu_is_text(install))
			continue;
		pr_info("ksu-shim: mntns_operations @%lx (get=%lx put=%lx install=%lx)\n",
			a, get, put, install);
		return a;
	}
	return 0;
}

/* ---------------- __tracepoint_sys_enter ----------------
 * 用 __start___tracepoints_ptrs（__start_ 前缀 → 在 kallsyms 里）
 * 遍历指针表（PREL32 相对偏移），比对 tp->name == "sys_enter"。
 */
static unsigned long ksu_resolve_tracepoint_sys_enter(void)
{
	unsigned long lo = kallsyms_lookup_name("__start___tracepoints_ptrs");
	unsigned long hi = kallsyms_lookup_name("__stop___tracepoints_ptrs");
	unsigned long p;

	if (!lo || !hi || hi <= lo || (hi - lo) > 0x100000UL)
		return 0;

	for (p = lo; p + 4 <= hi; p += 4) {
		s32 off;
		unsigned long tp, nm;

		if (ksu_safe_read(&off, (const void *)p, 4) < 0)
			break;
		tp = (unsigned long)((long)p + off);     /* PREL32：相对自身 */
		if (!ksu_is_kptr(tp))
			continue;
		if (ksu_safe_read(&nm, (const void *)tp, 8) < 0)
			continue;
		if (ksu_str_eq(nm, "sys_enter")) {
			pr_info("ksu-shim: __tracepoint_sys_enter @%lx\n", tp);
			return tp;
		}
	}
	return 0;
}

/* ================= 统一入口 ================= */

static struct {
	const char *name;
	unsigned long (*resolve)(void);
	unsigned long cached;
	bool done;
} ksu_data_resolvers[] = {
	{ "init_mm",                ksu_resolve_init_mm,                0, false },
	{ "selinux_state",          ksu_resolve_selinux_state,          0, false },
	{ "selinux_blob_sizes",     ksu_resolve_blob_sizes,             0, false },
	{ "mntns_operations",       ksu_resolve_mntns_operations,       0, false },
	{ "__tracepoint_sys_enter", ksu_resolve_tracepoint_sys_enter,   0, false },
};

static void ksu_shim_post_init(void)
{
	unsigned long real;
	static bool once;

	if (once)
		return;
	once = true;

	real = ksu_shim_data_addr("selinux_blob_sizes");
	if (real && (void *)real != (void *)&selinux_blob_sizes) {
		memcpy(&selinux_blob_sizes, (const void *)real, sizeof(selinux_blob_sizes));
		pr_info("ksu-shim: selinux_blob_sizes 已拷入 (lbs_cred=%d lbs_task=%d)\n",
			selinux_blob_sizes.lbs_cred, selinux_blob_sizes.lbs_task);
	}
}

unsigned long ksu_shim_data_addr(const char *name)
{
	unsigned long addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(ksu_data_resolvers); i++) {
		if (strcmp(ksu_data_resolvers[i].name, name) != 0)
			continue;
		if (!ksu_data_resolvers[i].done) {
			ksu_data_resolvers[i].done = true;
			addr = find_kernel_symbol_exact(name);      /* 若将来开了 KALLSYMS_ALL */
			if (!addr)
				addr = ksu_data_resolvers[i].resolve();
			ksu_data_resolvers[i].cached = addr;
			if (addr)
				pr_info("ksu-shim: 数据符号 %s 解析成功 @%lx\n", name, addr);
			else
				pr_warn("ksu-shim: 数据符号 %s 解析失败（将使用哑对象）\n", name);
		}
		return ksu_data_resolvers[i].cached;
	}
	pr_warn_once("ksu-shim: 未知数据符号 %s\n", name);
	return 0;
}

bool ksu_shim_resolved(const char *name)
{
	return ksu_shim_data_addr(name) != 0;
}

/* 哑对象：保证解析失败时不空指针崩溃 */
struct selinux_state ksu_dummy_selinux_state;
struct lsm_blob_sizes ksu_dummy_selinux_blob_sizes;
struct mm_struct ksu_dummy_init_mm;
const struct proc_ns_operations ksu_dummy_mntns_operations;

/* init_mm 哑对象：给它一张清零页当 pgd → pgd_none() 为真 → KSU 走失败分支，不会 oops */
static pgd_t *ksu_dummy_pgd;

void *ksu_shim_data_or_dummy(const char *name, void *dummy)
{
	unsigned long a = ksu_shim_data_addr(name);

	ksu_shim_post_init();

	if (a)
		return (void *)a;
	if (!strcmp(name, "init_mm")) {
		if (!ksu_dummy_pgd) {
			ksu_dummy_pgd = (pgd_t *)__get_free_page(GFP_KERNEL);
			if (ksu_dummy_pgd)
				clear_page(ksu_dummy_pgd);
		}
		if (ksu_dummy_pgd)
			ksu_dummy_init_mm.pgd = ksu_dummy_pgd;
	}
	return dummy;
}

/* ------------------------------------------------------------------
 * selinux_blob_sizes 需要【模块内真对象】（objsec.h 内联函数引用它，宏够不着）
 * ------------------------------------------------------------------ */
struct lsm_blob_sizes selinux_blob_sizes;

/* ------------------------------------------------------------------
 * __tracepoint_sys_enter 同样被头文件里的 tracepoint 宏引用，
 * 先放模块内对象让链接通过；Phase 5 会改用 ksu_shim_data_addr() 取真地址。
 * ------------------------------------------------------------------ */
struct tracepoint __tracepoint_sys_enter;
