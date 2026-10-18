# KernelSU for MegaOS

> **本仓库是 [KernelSU](https://github.com/tiann/KernelSU) 的非官方 LKM 移植分支**，面向
> **H3C MegaBook 14 / MegaOS（Android 14，内核 6.12.30）**。
> 基于上游 v3.3.1 源码，只做本设备的 x86_64 LKM 适配，**不修改、不重新编译厂商内核**。
>
> - 发布版本：`megaos-6.12.30-r1`（命名规则 `megaos-<内核>-r<修订>`）
> - 模块产物：`lkm-x86_64-megaos-android14-6.12_kernelsu.ko`
> - 构建入口：`kernel/build-megaos-x64.sh`
> - 与 KernelSU 上游无隶属关系；上游相关问题请提交到 [tiann/KernelSU](https://github.com/tiann/KernelSU)。

This is an **unofficial community port** of KernelSU for the H3C MegaBook 14
(MegaOS / Android 14, kernel 6.12.30). It is an LKM-only adaptation: the stock
vendor kernel is left untouched.

## 状态

已在本机验证：管理器显示“已安装”，`su` 可用。

## 构建

```bash
./kernel/build-megaos-x64.sh                       # persistent 日志默认开启
./kernel/build-megaos-x64.sh --no-persist-log      # 关闭 persistent 日志
./kernel/build-megaos-x64.sh --diag                # 打开 panic 转储
./kernel/build-megaos-x64.sh --out /tmp/kernelsu.ko
```

上游文档仍保留在 [`docs/`](docs/) 与 [`website/`](website/)。
