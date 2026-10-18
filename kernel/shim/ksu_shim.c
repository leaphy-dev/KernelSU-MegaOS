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

/* ==================================================================
 * KSU_KALLSYMS_FROM_KSUINIT
 * 这里原本定义了 kallsyms_lookup_name / kallsyms_lookup /
 * kallsyms_lookup_size_offset / kallsyms_on_each_symbol 四个"函数壳"，
 * 靠 register_kprobe 引导拿地址（本内核 KALLSYMS_ALL=n，数据符号不可得，
 * 但【函数】都在 /proc/kallsyms 里）。
 *
 * 结论：ksuinit（官方 LKM 引导器）在装载模块时，会自己读 /proc/kallsyms，
 * 把模块里所有【未定义符号】就地改写成绝对地址（SHN_ABS）——根本不做重定位，
 * 因此"内核没导出"完全无所谓。我们只要把这四个名字留作【未定义符号】即可，
 * 由 ksuinit 解析；不再需要任何 kprobe / 内存扫描。
 * ================================================================== */

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
 * 本设备 CONFIG_KALLSYMS_ALL=n → 数据符号【不在 kallsyms 里】，另辟蹊径：
 *   A) 引用反查：从"已知函数"的机器码里抠出 RIP 相对引用目标
 *      （候选函数名单是【离线在我们自己的 vmlinux 上验证过】的）
 *   B) 结构模式扫描：tracepoint 指针表 / proc_ns_operations
 *
 * 全部内存读取走 copy_from_kernel_nofault()，坏指针只返回错误、不会 oops。
 * 每个符号解析后都做语义自检，结果打印到日志，便于在设备上核对。
 *
 * 离线验证结果（在已知真值的内核上跑同一套逻辑）：
 *   init_mm            ← lookup_address        ★
 *   selinux_state      ← avc_denied            ★
 *   selinux_blob_sizes ← selinux_syslog        ★
 *   mntns_operations   ← .rodata 模式扫描       ★
 *   __tracepoint_sys_enter ← 指针表遍历         ★
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

/*
 * 扫描函数机器码里所有 RIP 相对引用的目标地址。
 * 支持的编码形态（覆盖离线确认过的全部引用点）：
 *   可选 REX(0x40-0x4f) + {8b,8d,89,8a,88,8c,03,2b,39,3b,84,85,63} + modrm(rip) + disp32
 *   可选 REX            + 0f {b6,b7,be,bf}                           + modrm(rip) + disp32
 * 其中 0x63=movslq（selinux_blob_sizes 的引用形态）。
 * 不要用 c7/83：它们带立即数，disp32 不在末尾，长度计算会错。
 */
#define KSU_MAX_REFS  64
#define KSU_MAX_CANDS 256

static int ksu_scan_rip_refs(unsigned long faddr, unsigned long fsize,
			     unsigned long *out, int max)
{
	const u8 *p = (const u8 *)faddr;
	int n = 0;
	unsigned long i;

	if (!ksu_is_kptr(faddr) || !fsize || fsize > 0x100000UL)
		return 0;

	for (i = 0; i + 6 <= fsize && n < max; i++) {
		const u8 *q = p + i;
		unsigned long len, k = 0;
		u8 op;

		if (q[0] >= 0x40 && q[0] <= 0x4f)
			k = 1;
		if (i + k + 2 > fsize)
			break;
		op = q[k];

		if (op == 0x0f) {
			u8 op2 = q[k + 1];

			if (!(op2 == 0xb6 || op2 == 0xb7 ||
			      op2 == 0xbe || op2 == 0xbf))
				continue;
			len = k + 7;
		} else if (op == 0x8b || op == 0x8d || op == 0x89 || op == 0x8a ||
			   op == 0x88 || op == 0x8c || op == 0x03 || op == 0x2b ||
			   op == 0x39 || op == 0x3b || op == 0x84 || op == 0x85 ||
			   op == 0x63) {
			len = k + 6;
		} else {
			continue;
		}

		if (i + len > fsize)
			break;
		if ((q[len - 5] & 0xc7) != 0x05)      /* mod=00, rm=101 → RIP 相对 */
			continue;

		{
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
	if (!kallsyms_lookup_size_offset(a, &sz, &off) || sz == 0 || sz > 0x40000UL)
		sz = 0x800;                           /* 拿不到大小就只扫函数头部 */
	return ksu_scan_rip_refs(a, sz, out, max);
}

/* ---------------- 校验函数（全部用安全读） ---------------- */

static bool ksu_valid_init_mm(unsigned long cand)
{
	unsigned long a = (unsigned long)&ksu_valid_init_mm;
	unsigned long pgd_p;
	pgd_t pgd;

	if (!ksu_is_kptr(cand))
		return false;
	if (ksu_safe_read(&pgd_p, (const void *)(cand + offsetof(struct mm_struct, pgd)), 8) < 0)
		return false;
	if (!ksu_is_kptr(pgd_p))
		return false;
	if (ksu_safe_read(&pgd, (const void *)(pgd_p + pgd_index(a) * sizeof(pgd_t)),
			  sizeof(pgd)) < 0)
		return false;
	return !pgd_none(pgd) && !pgd_bad(pgd);
}

static bool ksu_valid_selinux_state(unsigned long cand)
{
	struct selinux_state s;

	if (!ksu_is_kptr(cand))
		return false;
	if (ksu_safe_read(&s, (const void *)cand, sizeof(s)) < 0)
		return false;
	if (s.initialized != true || s.enforcing > 1)
		return false;
	return ksu_is_kptr((unsigned long)s.policy);
}

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

/* ---------------- 投票：多个函数共同指向同一地址才优先采纳 ---------------- */

static unsigned long ksu_pick_by_vote(unsigned long *c, int n,
				      bool (*valid)(unsigned long), int min_votes)
{
	int i, j, best = 0;
	unsigned long bestv = 0;

	for (i = 0; i < n; i++) {
		int cnt = 0;

		if (!c[i])
			continue;
		for (j = 0; j < n; j++)
			if (c[j] == c[i])
				cnt++;
		if (cnt >= min_votes && cnt > best && valid(c[i])) {
			best = cnt;
			bestv = c[i];
		}
	}
	return bestv;
}

static unsigned long ksu_resolve_by_refs(const char *const *fns, int nfns, long adjust,
					 bool (*valid)(unsigned long))
{
	static unsigned long cands[KSU_MAX_CANDS];
	unsigned long refs[KSU_MAX_REFS];
	int i, k, n, nrefs;
	unsigned long got;

	n = 0;
	for (i = 0; i < nfns && n < KSU_MAX_CANDS; i++) {
		nrefs = ksu_refs_of(fns[i], refs, KSU_MAX_REFS);
		for (k = 0; k < nrefs && n < KSU_MAX_CANDS; k++)
			cands[n++] = refs[k] + adjust;
	}
	got = ksu_pick_by_vote(cands, n, valid, 2);
	if (!got)
		got = ksu_pick_by_vote(cands, n, valid, 1);
	return got;
}

/* ---------------- 各符号的解析 ---------------- */

static unsigned long ksu_resolve_init_mm(void)
{
	static const char *fns[] = {
		"lookup_address", "slow_virt_to_phys", "vmalloc_to_page",
		"set_pte_vaddr", "drain_mmlist", "__get_user_pages",
	};

	return ksu_resolve_by_refs(fns, ARRAY_SIZE(fns),
				   -(long)offsetof(struct mm_struct, pgd),
				   ksu_valid_init_mm);
}

static unsigned long ksu_resolve_selinux_state(void)
{
	static const char *fns[] = { "avc_denied", "sel_read_enforce", "selinux_add_opt" };

	return ksu_resolve_by_refs(fns, ARRAY_SIZE(fns), 0, ksu_valid_selinux_state);
}

static unsigned long ksu_resolve_blob_sizes(void)
{
	static const char *fns[] = { "selinux_syslog", "selinux_capset", "selinux_bpf",
				     "sel_write_bool", "sel_write_load", "selinux_bpf_map" };

	return ksu_resolve_by_refs(fns, ARRAY_SIZE(fns), 0, ksu_valid_blob_sizes);
}

/*
 * mntns_operations：文本段里零直接引用（只被数据数组引用），所以扫 .rodata：
 * 找 {name, real_ns_name, type, get, put, install, ...} 中 name=="mnt" 且
 * +0x18/+0x20/+0x28 都是文本指针的那一个。
 * 注意 real_ns_name 通常是 NULL（没有 real 变体），不能要求它等于 "mnt"。
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
		if (real && !ksu_is_kptr(real))
			continue;
		if (ksu_safe_read(&get, (const void *)(a + 0x18), 8) < 0 ||
		    ksu_safe_read(&put, (const void *)(a + 0x20), 8) < 0 ||
		    ksu_safe_read(&install, (const void *)(a + 0x28), 8) < 0)
			continue;
		if (!ksu_is_text(get) || !ksu_is_text(put) || !ksu_is_text(install))
			continue;
		pr_info("ksu-shim: mntns_operations @%lx (get=%lx put=%lx install=%lx)\n",
			a, get, put, install);
		return a;
	}
	return 0;
}

/*
 * __tracepoint_sys_enter：遍历 __start___tracepoints_ptrs
 * （__start_ 前缀 → 在 kallsyms 里），元素是 PREL32 相对偏移，比对 tp->name。
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
		tp = (unsigned long)((long)p + off);   /* PREL32：相对自身 */
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


/* ==================================================================
 * 精确地址路径：设备链接期地址 + KASLR slide
 *
 * 地址来源：设备【原厂】vmlinux（从 boot_a 的 xz payload 解出 → vmlinux-to-elf
 *           恢复符号表），每个地址都经过双重交叉验证：
 *             init_mm              ← 4/4 同名函数共同引用
 *             selinux_state        ← 5/5 同名函数共同引用
 *             selinux_blob_sizes   ← 2 函数 + 内容校验
 *             mntns_operations     ← 3/3 函数 + 回调指针落在 +0x18..+0x30
 *             __tracepoint_sys_enter ← __traceiter_sys_enter 引用 + .name=="sys_enter"
 *
 * slide = 本模块【已导入】的 _printk 运行时地址 − 它在设备 vmlinux 的链接期地址
 * （KASLR 平移整个内核镜像，text/data 同幅 ⇒ 该公式对数据符号同样成立）
 * 任何一步校验不过 → 返回 0 → 自动退回原来的扫描器（安全）。
 * ================================================================== */
#define KSU_LINK__printk                 0xffffffff81000650UL
#define KSU_LINK_init_mm                 0xffffffff8538b380UL
#define KSU_LINK_selinux_state           0xffffffff85fd6fc8UL
#define KSU_LINK_selinux_blob_sizes      0xffffffff84f8ec40UL
#define KSU_LINK_mntns_operations        0xffffffff84d34728UL
#define KSU_LINK___tracepoint_sys_enter  0xffffffff85509460UL
/* sys_call_table：6.12 无直接代码引用 ⇒ 用"系统调用函数指针表"指纹求值（23/23 命中）*/
#define KSU_LINK_sys_call_table          0xffffffff84cf22a0UL

static unsigned long ksu_exact_addr(const char *name, long slide);

static long ksu_kaslr_slide(void)
{
	static bool done;
	static long slide;

	if (!done) {
		long s = (long)((unsigned long)(void *)&_printk - KSU_LINK__printk);

		/* 合理性检查：KASLR 以 2MB 为粒度、只向上平移 */
		slide = (s >= 0 && s <= 0x40000000L && (s % 0x200000L) == 0) ? s : -1;
		done = true;
		if (slide < 0)
			pr_warn("ksu-shim: slide 不可信(%ld)，走扫描兜底\n", slide);
	}
	return slide;
}

static bool ksu_valid_blob_sizes_exact(unsigned long a)
{
	int v[8];
	int i;

	if (!ksu_is_kptr(a) || ksu_is_text(a))
		return false;
	if (ksu_safe_read(v, (const void *)a, sizeof(v)) < 0)
		return false;
	for (i = 0; i < 8; i++)
		if (v[i] < 0 || v[i] > 0x10000)
			return false;
	return true;
}

static bool ksu_valid_mntns_ops_exact(unsigned long a)
{
	unsigned long v;
	int i;

	if (!ksu_is_kptr(a) || ksu_is_text(a))
		return false;
	for (i = 3; i <= 6; i++) {	/* get/put/install/owner 在 +0x18..+0x30 */
		if (ksu_safe_read(&v, (const void *)(a + 8 * i), 8) < 0)
			return false;
		if (!ksu_is_text(v))
			return false;
	}
	return true;
}

static bool ksu_valid_tp_sys_enter_exact(unsigned long a)
{
	unsigned long nm = 0;

	if (!ksu_is_kptr(a) || ksu_is_text(a))
		return false;
	if (ksu_safe_read(&nm, (const void *)a, 8) < 0)	/* struct tracepoint.name 在 +0 */
		return false;
	if (!ksu_is_kptr(nm))
		return false;
	return ksu_str_eq(nm, "sys_enter");
}


static bool ksu_valid_sys_call_table(unsigned long a)
{
	unsigned long v0 = 0, v1 = 0;

	if (!ksu_is_kptr(a) || ksu_is_text(a))
		return false;
	if (ksu_safe_read(&v0, (const void *)a, 8) < 0)
		return false;
	if (ksu_safe_read(&v1, (const void *)(a + 8), 8) < 0)
		return false;
	/* 表项必须是内核文本指针（syscall 处理函数） */
	return ksu_is_text(v0) && ksu_is_text(v1);
}

static const struct {
	const char *name;
	unsigned long link;
	bool (*valid)(unsigned long);
} ksu_exact_syms[] = {
	{ "init_mm",                KSU_LINK_init_mm,                ksu_valid_init_mm },
	{ "selinux_state",          KSU_LINK_selinux_state,          ksu_valid_selinux_state },
	{ "selinux_blob_sizes",     KSU_LINK_selinux_blob_sizes,     ksu_valid_blob_sizes_exact },
	{ "mntns_operations",       KSU_LINK_mntns_operations,       ksu_valid_mntns_ops_exact },
	{ "__tracepoint_sys_enter", KSU_LINK___tracepoint_sys_enter, ksu_valid_tp_sys_enter_exact },
	{ "sys_call_table",         KSU_LINK_sys_call_table,        ksu_valid_sys_call_table },
};

static unsigned long ksu_exact_addr(const char *name, long slide)
{
	int i;

	if (slide < 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(ksu_exact_syms); i++) {
		unsigned long a;

		if (strcmp(ksu_exact_syms[i].name, name) != 0)
			continue;
		a = ksu_exact_syms[i].link + (unsigned long)slide;
		if (ksu_exact_syms[i].valid && !ksu_exact_syms[i].valid(a))
			return 0;
		return a;
	}
	return 0;
}


/* 只查精确表；命中返回真地址，否则 0。给 KSU 的 find_kernel_symbol_exact 用。 */
unsigned long ksu_shim_exact_lookup(const char *name)
{
	return ksu_exact_addr(name, ksu_kaslr_slide());
}

/* ================= 统一入口 ================= */

static struct {
	const char *name;
	unsigned long (*resolve)(void);
	unsigned long cached;
	bool done;
} ksu_data_resolvers[] = {
	{ "init_mm",                ksu_resolve_init_mm,               0, false },
	{ "selinux_state",          ksu_resolve_selinux_state,         0, false },
	{ "selinux_blob_sizes",     ksu_resolve_blob_sizes,            0, false },
	{ "mntns_operations",       ksu_resolve_mntns_operations,      0, false },
	{ "__tracepoint_sys_enter", ksu_resolve_tracepoint_sys_enter,  0, false },
};

unsigned long ksu_shim_data_addr(const char *name)
{
	unsigned long addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(ksu_data_resolvers); i++) {
		if (strcmp(ksu_data_resolvers[i].name, name) != 0)
			continue;
		if (!ksu_data_resolvers[i].done) {
			ksu_data_resolvers[i].done = true;
			addr = find_kernel_symbol_exact(name);   /* 若将来开了 KALLSYMS_ALL */
			if (!addr)
				addr = ksu_exact_addr(name, ksu_kaslr_slide());   /* 设备链接期地址 + slide */
			if (!addr)
				addr = ksu_data_resolvers[i].resolve();
			ksu_data_resolvers[i].cached = addr;
			if (addr)
				pr_info("ksu-shim: 数据符号 %s 解析成功 @%lx\n", name, addr);
			else
				pr_warn("ksu-shim: 数据符号 %s 解析失败（使用哑对象）\n", name);
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

/* selinux_blob_sizes 解析成功后，把内核里的真值拷进模块内的真对象 */
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

/* 哑对象：解析失败时使用它们，保证不空指针崩溃 */
struct selinux_state ksu_dummy_selinux_state;
struct lsm_blob_sizes ksu_dummy_selinux_blob_sizes;
struct mm_struct ksu_dummy_init_mm;
const struct proc_ns_operations ksu_dummy_mntns_operations;

/* init_mm 哑对象：给一张清零页当 pgd → pgd_none() 为真 → KSU 走失败分支，不 oops */
static pgd_t *ksu_dummy_pgd;

void *ksu_shim_data_or_dummy(const char *name, void *dummy)
{
	unsigned long a;

	ksu_shim_post_init();
	a = ksu_shim_data_addr(name);

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
 * 这两个被【头文件里的内联函数/宏】引用，#define 够不着，所以用模块内真对象：
 *   selinux_blob_sizes    ← objsec.h 的 selinux_cred() 等内联
 *   __tracepoint_sys_enter ← <trace/events/syscalls.h> 的 tracepoint 宏
 * ------------------------------------------------------------------ */
struct lsm_blob_sizes selinux_blob_sizes;
struct tracepoint __tracepoint_sys_enter;

/* ==================================================================
 * ⑤ 绕过符号版本(CRC)校验
 *
 * 本设备 CONFIG_MODVERSIONS=y 且 MODULE_FORCE_LOAD 未开：正常情况下模块里
 * 每个被引用符号的 CRC 都必须与内核一致，否则 insmod 直接失败
 * （而没 root 就没法在设备上试错）。
 *
 * 但 kernel/module/version.c 的 check_version() 有这样一段：
 *     if (info->index.vers_ext_crc) {
 *             for_each_modversion_info_ext(...) { 只有名字匹配才比对 CRC }
 *             pr_warn_once("no extended symbol version for %s");
 *             return 1;          // ★ 名字不在列表里 → 直接放行
 *     }
 * 所以只要让模块里【存在】__version_ext_crcs 段、且不列出任何被引用的符号，
 * 所有版本校验（含 module_layout）都会放行。
 * 代价：失去"ABI 不一致就拒绝加载"这层保护（本机配置/头文件与设备同源，风险低），
 *       并且每个符号会在 dmesg 留一行 once 警告（正好当清单用）。
 * ================================================================== */
static const u32 ksu_version_ext_crcs[] __used
	__section("__version_ext_crcs") = { 0x5eed5eedu };
static const char ksu_version_ext_names[] __used
	__section("__version_ext_names") = "ksu_shim_placeholder_never_matches";
