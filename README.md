# GhostLock OPPO Find N2 Exploit

> 基于 CVE-2026-43499 (GhostLock) 的 Android 内核提权漏洞利用链

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Kernel: 5.10.236](https://img.shields.io/badge/Kernel-5.10.236-green.svg)]()
[![Device: OPPO Find N2](https://img.shields.io/badge/Device-OPPO%20Find%20N2-orange.svg)]()

## 项目概述

本项目是针对 **OPPO Find N2 (SM8475/CPH2413)** 设备的 GhostLock 内核漏洞利用，基于 [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) 开源研究项目适配。

### 当前项目状态

| 阶段 | 状态 | 说明 |
|------|------|------|
| KernelSnitch mm_struct leak | ✅ 完成 | 修复 futex_hashsize 后成功泄漏 mm_struct |
| GhostLock FUTEX PI 触发 | ✅ 完成 | 3 futex words + 3 threads → -EDEADLK |
| 所有结构体偏移验证 | ✅ 完成 | 45 个 pahole 偏移 + 18 个 nm 符号偏移全部正确 |
| **KASLR bypass (slide)** | ❌ **阻塞** | **无 syscall 在 waiter 位置写入用户可控数据** |
| pipe 物理读写 | ⏳ 待测 | 依赖 KASLR bypass |
| 提权 (cred + SELinux) | ⏳ 待测 | 依赖 pipe physrw |

### 核心阻塞问题

**waiter 位置**: `stack_top - 0x358` (856B) — 从 boot-2.img 提取的内核精确验证

需要一个 syscall 在 `stack_top - 0x358` 处写入用户可控数据。已测试的所有 stack reclaim 方法均失败：

| 方法 | 结果 | 差距 |
|------|------|------|
| pselect (NFDS=384) | fd_set 在 stack_top-0x1f8 | 差 352B |
| pselect (NFDS=1024) | fd_set 在堆上 (kvmalloc) | 不在栈上 |
| binder ioctl | EACCES (errno=13) | shell 用户无权限 |
| process_vm_readv | 帧仅 160B | 差 696B |
| PR_SET_MM_MAP | EPERM | Android 阻止 |
| setsockopt MCAST | EADDRNOTAVAIL | IPv6 限制 |
| keyctl | EOPNOTSUPP | 不支持 |
| timerfd | ENOSYS | seccomp 阻止 |

> [!NOTE]
> NebuSec 表示下一篇 Android GhostLock blog 将讨论 Android 上的 stack reclaim 和 ASLR bypass 方法。

## 设备信息

| 项目 | 值 |
|------|-----|
| 型号 | OPPO PGU110 (Find N2) |
| 芯片 | Snapdragon 8+ Gen 1 (SM8475) |
| 内核 | Linux 5.10.236-android12-9 GKI |
| Android | 16 |
| Build | PGU110_16.0.5.1001(CN01) |
| CONFIG_NR_CPUS | 32 (possible=0-7, online=6) |
| CONFIG_FUTEX_PI | y |
| CONFIG_UNMAP_KERNEL_AT_EL0 | y (KPTI enabled) |

## 核心技术分析

### GhostLock 漏洞 (CVE-2026-43499)

`remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`。在 proxy 路径中，`current` 是 requeuer 而非 waiter，导致 waiter 的 `pi_blocked_on` 变成悬空指针。

### 帧大小分析 (boot-2.img 提取内核)

| 函数 | 帧大小 | 来源 |
|------|--------|------|
| sys_futex | 0x10 (16B) | STP X29,X30,[SP,#-0x10]! |
| do_futex | 0x1c0 (448B) | SUB SP,SP,#0x1c0 |
| futex_wait_requeue_pi | 0x1a0 (416B) | SUB SP,SP,#0x1a0 |
| **总 futex 链** | **0x3d0 (976B)** | |
| **waiter 距栈顶** | **0x358 (856B)** | 0x3d0 - 0x78 |

> ⚠️ **注意**: 服务器编译的 vmlinux 帧大小与设备不匹配！do_futex: 服务器=0x130 vs 设备=**0x1c0**。所有分析必须以 boot-2.img 提取内核为准。

### pselect 链分析

| 函数 | 帧大小 |
|------|--------|
| sys_pselect6 | 0x90 (144B) |
| core_sys_select | 0x1d0 (464B) |
| do_select | 0x390 (912B) |
| **总计** | **0x610 (1552B)** |

- fd_set 位置: stack_top - 0x1f8 (504B) — 在 core_sys_select 帧内 SP+0x68
- waiter 位置: stack_top - 0x358 (856B) — 在 do_select 帧内
- **差距: 352B — fd_set 无法触及 waiter**
- do_select 在 waiter 位置 (SP+0x298) 没有任何数据写入

## 文件结构

```
oppo-ghostlock/
├── README.md                          # 本文件
├── AGENTS.md                          # AI Agent 指南
├── HANDOFF.md                         # 会话交接文档
├── TROUBLESHOOTING.md                 # 问题排查手册
├── FAQ.md                             # 常见问题
├── CONTRIBUTING.md                    # 贡献指南
├── CHANGELOG.md                       # 版本更新日志
├── exploit/                           # exploit 源代码与构建
│   ├── Makefile                       # 构建脚本
│   ├── src/                           # 源代码
│   │   ├── main.c                     # 主入口
│   │   ├── util.c                     # KernelSnitch 设置与工具函数
│   │   ├── slide.c                    # KASLR bypass
│   │   ├── fops.c                     # file_operations 利用
│   │   ├── pipe.c                     # pipe 物理读写
│   │   ├── root.c                     # root 提权
│   │   ├── preload.c                  # LD_PRELOAD 入口
│   │   ├── su_daemon.c               # su 守护进程
│   │   ├── su_blob.S                  # su 二进制嵌入
│   │   ├── wallpaper_blob.S           # wallpaper 嵌入
│   │   ├── common.h                   # 公共定义与偏移
│   │   └── kernelsnitch/              # KernelSnitch 库
│   ├── targets/oppo-find_n2/          # 设备特定配置
│   │   └── target.h                   # 内核偏移量
│   └── test-programs/                 # 测试程序
│       ├── test_binder.c
│       ├── test_futex.c
│       └── ...
├── analysis-scripts/                  # 分析脚本
├── docs/                              # 文档
├── exploit-server/                    # exploit 服务器
└── extract-vmlinux                    # vmlinux 提取工具
```

## 编译与部署

### 编译 exploit

```bash
cd exploit

# 使用 Makefile (推荐)
make                    # 自动检测 NDK 路径
make NDK=/path/to/ndk  # 指定 NDK 路径

# 或手动编译
NDK=/tmp/ndk_extract/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang
SYSROOT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot

$CC --target=aarch64-linux-android35 --sysroot=$SYSROOT \
  -I. -Isrc -Itargets/oppo-find_n2 \
  -O2 -fPIC -shared \
  -DTARGET_CONFIG_H='"targets/oppo-find_n2/target.h"' \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
  src/preload.c src/su_blob.S src/wallpaper_blob.S \
  -pthread -o preload.so
```

### 部署到设备

```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

## 下一步计划

1. **等待 NebuSec Android blog** — 他们将讨论 Android 上的 stack reclaim 和 ASLR bypass
2. **尝试 io_uring** — 可能有更深的调用链和用户可控数据
3. **nfsetsockopt** — Netfilter setsockopt 可能有不同的栈布局
4. **寻找 CAP_SYS_PTRACE helper** — 用 PR_SET_MM_MAP

## 参考资料

- [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) - 原始 exploit 项目
- [GhostLock CVE-2026-43499](https://nebusec.ai/research/ionstack-part-2/) - 内核漏洞分析
- [IonStack Part I](https://nebusec.ai/research/ionstack-part-1/) - Firefox 漏洞分析
- [CyberMeowfia PoC](https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c) - 8 种 stack reclaim 方法测试

## 免责声明

本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。

## License

Apache License 2.0
