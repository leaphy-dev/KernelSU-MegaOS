[English](README.md) | [Español](README_ES.md) | **简体中文** | [繁體中文](README_TW.md) | [日本語](README_JP.md) | [한국어](README_KR.md) | [Polski](README_PL.md) | [Português (Brasil)](README_PT-BR.md) | [Türkçe](README_TR.md) | [Русский](README_RU.md) | [Tiếng Việt](README_VI.md) | [Indonesia](README_ID.md) | [עברית](README_IW.md) | [हिंदी](README_IN.md) | [Italiano](README_IT.md)

# KernelSU

> [!NOTE]
> **MegaOS 移植分支 / MegaOS port branch**
>
> 本分支是面向 **H3C MegaBook 14 / MegaOS（Android 14，内核 6.12.30）** 的非官方
> x86_64 LKM 适配，**不修改厂商内核**，与 KernelSU 上游项目无隶属关系。
>
> This branch is an unofficial x86_64 LKM adaptation for the **H3C MegaBook 14**
> running **MegaOS (Android 14, kernel 6.12.30)**. The stock vendor kernel is left
> untouched. It is not affiliated with the KernelSU upstream project.
>
> Release / 版本 `megaos-6.12.30-r2` ·
> module / 模块 `lkm-x86_64-megaos-android14-6.12_kernelsu.ko` ·
> build / 构建 `kernel/build-megaos-x64.sh`

<img src="https://kernelsu.org/logo.png" style="width: 96px;" alt="logo">

一个 Android 上基于内核的 root 方案。

[![Latest release](https://img.shields.io/github/v/release/tiann/KernelSU?label=Release&logo=github)](https://github.com/tiann/KernelSU/releases/latest)
[![Weblate](https://img.shields.io/badge/Localization-Weblate-teal?logo=weblate)](https://hosted.weblate.org/engage/kernelsu)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/KernelSU)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## 特性

- 基于内核的 `su` 和权限管理。
- 基于 [metamodules](https://kernelsu.org/zh_CN/guide/metamodule.html) 的模块系统：可插拔的模块架构。
- [App Profile](https://kernelsu.org/zh_CN/guide/app-profile.html): 把 Root 权限关进笼子里。

## 兼容状态

KernelSU 官方支持 GKI 2.0 的设备（内核版本5.10以上）；旧内核也是兼容的（最低4.14+），不过需要自己编译内核。

WSA, ChromeOS 和运行在容器上的 Android 也可以与 KernelSU 一起工作。

目前支持 `arm64-v8a` 和 `x86_64` 架构。

> [!CAUTION]
> 最近的内核版本引入了一项破坏性更改，导致 KernelSU 在 `x86_64` 上运行失败，甚至可能引发内核恐慌 (kernel panic)！请查看网站获取更多信息！

## 使用方法

- [安装教程](https://kernelsu.org/zh_CN/guide/installation.html)
- [如何构建？](https://kernelsu.org/zh_CN/guide/how-to-build.html)
- [官方网站](https://kernelsu.org/zh_CN/)

### MegaOS（H3C MegaBook 14）

本分支通过从 Windows 刷入预打包的 `boot_a` 镜像安装，不需要重新编译内核，也不需要 fastboot。
This branch is installed by flashing a pre-patched `boot_a` image from Windows.

**先决条件 / Prerequisites**

- **请先切换到 Windows 系统。** 安装脚本直接写 `\\.\PhysicalDrive0`，无法在 Android / Linux / WSL 中运行。
  **Boot into Windows first.** The installer writes directly to `\\.\PhysicalDrive0`; it cannot run from Android, Linux, or WSL.
- Windows 11 + **管理员** PowerShell。
  Windows 11 with an **Administrator** PowerShell.
- 从 Release 下载 `boot_a_megaos-6.12.30-r2.img`、`install-megaos.ps1`、`SHA256SUMS`。
  Download the three files from the release page.
- 保留原厂 `boot_a` 备份（安装脚本的 `-Backup` 会自动备份）。
  Keep a stock `boot_a` backup (the installer's `-Backup` does this automatically).

**安装 / Install**

1. 先启动到 Windows。
   Boot into Windows.
2. 将三个文件放在同一目录，并在该目录打开管理员 PowerShell。
   Put the three files in one folder and open an Administrator PowerShell there.
3. 运行安装脚本（校验 hash、备份 `boot_a`、写入并回读校验）：
   Run the installer (it checks the hash, backs up `boot_a`, writes, and verifies by reading back):

   ```powershell
   .\install-megaos.ps1 `
       -Image .\boot_a_megaos-6.12.30-r2.img `
       -ExpectedSha256 884152fe86348ed80ae05421e02d5de6b834a76ade35be23f9144984a7a5eb1b `
       -Backup -SetOneShotBoot
   ```

   源码树里同一脚本位于 `scripts/install-megaos.ps1`。
   In the source tree the same script is at `scripts/install-megaos.ps1`.

4. 安装官方 KernelSU 管理器 APK（`me.weishu.kernelsu`）。
   Install the official KernelSU manager APK (`me.weishu.kernelsu`).
5. 重启进入 MegaOS，管理器应显示“已安装”。
   Reboot into MegaOS; the manager should show **Installed**.

**回滚 / Rollback**

```powershell
.\install-megaos.ps1 -Restore .\boot_a-backup-YYYYmmdd-HHMMSS.img
```

> 仅适用于 H3C MegaBook 14 / 内核 `6.12.30` / `boot_a`。
> For H3C MegaBook 14 / kernel `6.12.30` / `boot_a` only.

## 参与翻译

要将 KernelSU 翻译成您的语言，或完善现有的翻译，请使用 [Weblate](https://hosted.weblate.org/engage/kernelsu/)。现已不再接受有关管理器翻译的PR，因为这会与Weblate冲突。

## 讨论

- Telegram: [@KernelSU](https://t.me/KernelSU)

## 安全性

有关报告 KernelSU 安全漏洞的信息，请参阅 [SECURITY.md](/SECURITY.md)。

## 许可证

- 目录 `kernel` 下所有文件为 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 `kernel` 目录的其他部分均为 [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)。

## 鸣谢

- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)：KernelSU 的灵感。
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具箱。
- [genuine](https://github.com/brevent/genuine/)：apk v2 签名验证。
- [Diamorphine](https://github.com/m0nad/Diamorphine)：一些 rootkit 技巧。
