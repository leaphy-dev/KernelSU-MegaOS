#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

/*
 * [KSU-X86-PORT] persistent 启动日志开关。
 *
 * 定义 KSU_X86_PERSISTENT_BOOT_LOG 时启用 ksu_blog()：日志顺序写入
 * /dev/block/by-name/persistent 的 512KB 偏移处（跨重启保留）。
 * 未定义时 ksu_blog() 编译为 no-op，不会打开任何设备。
 *
 * 打开：build-megaos-x64.sh（默认）
 * 关闭：build-megaos-x64.sh --no-persist-log
 */
#ifdef KSU_X86_PERSISTENT_BOOT_LOG
void ksu_blog(const char *fmt, ...);
#else
static inline void ksu_blog(const char *fmt, ...)
{
	(void)fmt;
}
#endif

#endif
