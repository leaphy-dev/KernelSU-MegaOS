/* SPDX-License-Identifier: GPL-2.0 */
/* KernelSU LKM 救援层 —— 数据对象访问宏（见 shim/ksu_shim.c） */
#ifndef __KSU_SHIM_H
#define __KSU_SHIM_H

#include <linux/types.h>
#include <linux/tracepoint-defs.h>

unsigned long ksu_shim_data_addr(const char *name);
void ksu_shim_data_retry(const char *name);
unsigned long ksu_shim_exact_lookup(const char *name);   /* 仅查精确表，无日志 */

/* [KSU-X86-PORT] IBT：间接调用内核函数前，把被封存的 endbr64 补回来 */
void ksu_ibt_ensure_endbr(void *addr);
void ksu_shim_ensure_all_endbr(void);
void *ksu_shim_data_or_dummy(const char *name, void *dummy);
bool ksu_shim_resolved(const char *name);

extern struct selinux_state ksu_dummy_selinux_state;
extern struct lsm_blob_sizes ksu_dummy_selinux_blob_sizes;
extern struct mm_struct ksu_dummy_init_mm;
extern const struct proc_ns_operations ksu_dummy_mntns_operations;

/*
 * 解析成功 → 真对象；失败 → 哑对象（保证不空指针崩溃）
 * 注意：本头必须在所有内核头之后 include（避免破坏 extern 声明）
 */
#define init_mm \
	(*(struct mm_struct *)ksu_shim_data_or_dummy("init_mm", &ksu_dummy_init_mm))
#define selinux_state \
	(*(struct selinux_state *)ksu_shim_data_or_dummy("selinux_state", &ksu_dummy_selinux_state))
#define mntns_operations \
	(*(const struct proc_ns_operations *)ksu_shim_data_or_dummy("mntns_operations", \
		(void *)&ksu_dummy_mntns_operations))

#endif /* __KSU_SHIM_H */
