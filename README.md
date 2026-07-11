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
| 所有偏移验证 | ✅ 完成 | vmlinux + pahole 双重验证 |
| KernelSnitch mm_struct leak | ❌ 阻塞 | KPTI 启用导致时序不准确 |
| GhostLock FUTEX PI 触发 | ✅ 完成 | 3 futex words + 3 threads → -EDEADLK |
| **KASLR bypass (slide)** | ❌ **阻塞** | **无 syscall 在 waiter 位置写入用户可控数据** |
| pipe 物理读写 | ⏳ 待测 | 依赖 KASLR bypass |
| 提权 (cred + SELinux) | ⏳ 待测 | 依赖 pipe physrw |

### 核心阻塞问题

**waiter 位置**: `stack_top - 0x2c8` (712B) — 从 vmlinux objdump 精确验证

需要一个 syscall 在 `stack_top - 0x2c8` 处写入用户可控数据。已测试的所有 stack reclaim 方法均失败：

| 方法 | 结果 | 差距 |
|------|------|------|
| pselect (NFDS=384) | fd_set 在 stack_top-0x1f8 | 差 208B |
| pselect (NFDS=1024) | fd_set 在堆上 (kvmalloc) | 不在栈上 |
| binder ioctl | EACCES (errno=13) | shell 用户无权限 |
| process_vm_readv | 帧仅 160B | 差 552B |
| PR_SET_MM_MAP | EPERM | Android 阻止 |

> [!NOTE]
> NebuSec 已确认将在下一篇 Android blog 中讨论 Android 上的 stack reclaim 和 ASLR bypass 方法。详见 [IonStack Part II](https://nebusec.ai/research/ionstack-part-2/)。

## 设备信息

| 项目 | 值 |
|------|-----|
| 型号 | OPPO PGU110 (Find N2) |
| 芯片 | Snapdragon 8+ Gen 1 (SM8475) |
| 内核 | Linux 5.10.236-android12-9 GKI |
| Android | 16 |
| Build | PGU110_16.0.5.1001(CN01) |
| CONFIG_NR_CPUS | 32 (possible=0-7, online=8) |
| CONFIG_FUTEX_PI | y |
| CONFIG_UNMAP_KERNEL_AT_EL0 | y (KPTI enabled) |

## 核心技术分析

### GhostLock 漏洞 (CVE-2026-43499)

`remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`。在 proxy 路径中，`current` 是 requeuer 而非 waiter，导致 waiter 的 `pi_blocked_on` 变成悬空指针。

### 帧大小分析 (vmlinux objdump 验证)

| 函数 | 帧大小 | 来源 |
|------|--------|------|
| __arm64_sys_futex | 0x70 (112B) | SUB SP,SP,#0x70 |
| do_futex | 0x130 (304B) | SUB SP,SP,#0x130 |
| futex_wait_requeue_pi | 0x1a0 (416B) | SUB SP,SP,#0x1a0 |
| **总 futex 链** | **0x340 (832B)** | |
| **waiter 距栈顶** | **0x2c8 (712B)** | 0x340 - 0x78 |

> [!WARNING]
> 之前的帧大小是错误的！sys_futex: 旧=0x10 vs 实际=**0x70**，do_futex: 旧=0x1c0 vs 实际=**0x130**。所有帧大小分析必须使用 OPPO 内核源码编译的 vmlinux。

### SLUB 分配器参数 (pahole 验证)

| 参数 | 值 | 验证方法 |
|------|-----|----------|
| MM_STRUCT_SZ | 0x3c0 (960B) | pahole: 952B + 8B cpu_bitmap |
| MM_ORDER | 3 | SLUB order 计算: 32KB slabs |
| objects_per_slab | 34 | 32768 / 960 = 34 |
| futex_hashsize | 2048 | 8 CPUs * 256 |

## 快速开始

### 环境要求

| 组件 | 版本 | 用途 |
|------|------|------|
| Android NDK | r29 | 交叉编译 exploit |
| ADB | 37.0+ | Android 调试 |
| Python | 3.8+ | 服务器脚本 |
| 目标设备 | OPPO Find N2 | exploit 目标 |

### 安装依赖

```bash
# macOS
brew install --cask android-ndk
brew install android-platform-tools

# 验证安装
$NDK_PATH/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang --version
adb version
```

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

### 验证成功

成功后会显示：
```
[+] preload starting pid=...
[+] startup context pid=... uid=0(root)
```

## 仓库目录结构

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
│   ├── .gitignore                     # 构建产物忽略
│   ├── src/                           # 源代码
│   │   ├── main.c                     # 主入口
│   │   ├── util.c                     # KernelSnitch 设置与工具函数
│   │   ├── slide.c                    # KASLR bypass (process_vm_readv)
│   │   ├── fops.c                     # file_operations 利用
│   │   ├── pipe.c                     # pipe 物理读写
│   │   ├── root.c                     # root 提权
│   │   ├── preload.c                  # LD_PRELOAD 入口
│   │   ├── su_daemon.c               # su 守护进程
│   │   ├── su_blob.S                  # su 二进制嵌入
│   │   ├── wallpaper_blob.S           # wallpaper 嵌入
│   │   ├── common.h                   # 公共定义与偏移
│   │   └── kernelsnitch/              # KernelSnitch 库
│   │       ├── kernelsnitch.h
│   │       ├── futex_hash.h           # futex 哈希 (已修复)
│   │       ├── utils.h
│   │       └── timeutils.h
│   ├── targets/oppo-find_n2/          # 设备特定配置
│   │   └── target.h                   # 内核偏移量 (pahole 验证)
│   └── test-programs/                 # 测试程序
│       ├── test_binder.c
│       ├── test_futex.c
│       ├── test_mcast.c
│       ├── test_pselect_nfds.c
│       ├── test_reclaim.c
│       ├── test_seccomp_futex.c
│       ├── test_stamp.c
│       ├── test_leak_mm.c             # mm_struct 泄漏方法测试
│       └── test_kernel_leak.c         # 内核信息泄漏测试
├── analysis-scripts/                  # 分析脚本
│   ├── find_deep_chains*.py           # 内核调用链分析
│   ├── inspect_elf.py                 # ELF 格式检查
│   ├── inspect_text.py                # .text 段检查
│   └── diagnose_callgraph.py          # 调用图诊断
├── docs/                              # 文档
│   ├── architecture.md
│   ├── setup.md
│   ├── best-practice.md
│   ├── knowledge-notes.md
│   └── adaptation-guide.md            # 适配指南
├── exploit-server/                    # exploit 服务器
│   ├── CVE-2026-10702/                # Firefox exploit
│   └── log_server.py                  # 日志服务器
└── extract-vmlinux                    # vmlinux 提取工具
```

## 文档导航

| 文档 | 说明 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI Agent 指南 |
| [HANDOFF.md](HANDOFF.md) | 会话交接文档 |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 问题排查手册 |
| [FAQ.md](FAQ.md) | 常见问题 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南 |
| [CHANGELOG.md](CHANGELOG.md) | 版本更新日志 |
| [docs/architecture.md](docs/architecture.md) | 架构设计文档 |
| [docs/setup.md](docs/setup.md) | 环境搭建与部署 |
| [docs/best-practice.md](docs/best-practice.md) | 开发最佳实践 |
| [docs/knowledge-notes.md](docs/knowledge-notes.md) | 技术知识沉淀 |
| [docs/adaptation-guide.md](docs/adaptation-guide.md) | 适配指南 |

## 下一步计划

1. **等待 NebuSec Android blog** — 他们将讨论 Android 上的 stack reclaim 和 ASLR bypass
2. **寻找替代 mm_struct 泄漏方法** — 当前 KernelSnitch 因 KPTI 失败
3. **尝试 io_uring** — 可能有更深的调用链和用户可控数据
4. **nfsetsockopt** — Netfilter setsockopt 可能有不同的栈布局

## 参考资料

- [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) - 原始 exploit 项目
- [GhostLock CVE-2026-43499](https://nebusec.ai/research/ionstack-part-2/) - 内核漏洞分析
- [IonStack Part I](https://nebusec.ai/research/ionstack-part-1/) - Firefox 漏洞分析
- [CyberMeowfia PoC](https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c) - 8 种 stack reclaim 方法测试

## 免责声明

本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。

## License

GPL License
