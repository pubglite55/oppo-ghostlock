# GhostLock OPPO Find N2 Exploit

> 基于 CVE-2026-43499 (GhostLock) 的 Android 内核提权漏洞利用链 — OPPO Find N2 适配

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Kernel: 5.10.236](https://img.shields.io/badge/Kernel-5.10.236-green.svg)]()
[![Device: OPPO Find N2](https://img.shields.io/badge/Device-OPPO%20Find%20N2-orange.svg)]()
[![Status: Research](https://img.shields.io/badge/Status-Research-yellow.svg)]()

## 项目概述

本项目是针对 **OPPO Find N2 (SM8475/CPH2413)** 设备的 GhostLock 内核漏洞利用，基于 [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) 开源研究项目适配。

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 到 7.1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞争条件触发。本项目的目标是在 OPPO Find N2 上复现并完成完整的提权链。

### 当前项目状态

| 阶段 | 状态 | 说明 |
|------|------|------|
| Firefox CVE-2026-10702 | ✅ 完成 | SpiderMonkey type confusion → fake TypedArray → AAW |
| KASLR bypass (slide) | ✅ 完成 | pselect side-channel 泄漏 nfulnl_logger |
| GhostLock FUTEX PI 触发 | ✅ 完成 | FUTEX_CMP_REQUEUE_PI ret=1 |
| KernelSnitch mm_struct 泄漏 | ✅ 完成 | pile-up ✅, hashsize ✅, bruteforce ✅ |
| sk_buff reclaim | ✅ 完成 | 4/4 send 成功 |
| slide pselect (栈覆盖) | ❌ **阻塞** | waiter 在 fd_set 数据下方 120 字节，fd_set bitmaps 无法到达 waiter 位置 |
| pipe physrw | ⏳ 待实现 | 依赖栈覆盖修复 |
| root (cred + SELinux) | ⏳ 待实现 | 依赖 pipe physrw |

## 核心特性

- **KernelSnitch mm_struct 泄漏** — 通过 futex hash 碰撞 + 时间差测量，成功从内核 direct-map 中定位 mm_struct 地址
- **KASLR bypass** — 利用 pselect side-channel 泄漏 nfulnl_logger 地址，推导 kernel base
- **GhostLock FUTEX PI 触发** — 通过 FUTEX_CMP_REQUEUE_PI 成功触发 rtmutex PI chain walk
- **sk_buff reclaim** — 成功将控制数据写入内核页
- **IDA 偏移验证** — 通过 IDA output.elf 验证所有关键内核符号地址和结构体偏移
- **帧大小修正** — 修正仓库中错误的帧大小数据 (sys_futex=0x90, do_futex=0x70, do_select=0x3C0)
- **自动化构建** — Makefile 自动检测 NDK 路径，一键编译 preload.so

## 技术栈

| 层级 | 技术 | 版本 |
|------|------|------|
| 目标内核 | Linux GKI | 5.10.236 |
| 交叉编译 | Android NDK | r29 |
| 编译器 | Clang | aarch64-linux-android35 |
| 分析工具 | IDA Pro | MCP 集成 |
| 设备交互 | ADB | 37.0+ |
| 漏洞类型 | GhostLock (CVE-2026-43499) | FUTEX_CMP_REQUEUE_PI |

## 快速开始

### 环境要求

| 组件 | 版本 | 用途 |
|------|------|------|
| Android NDK | r29 | 交叉编译 exploit |
| ADB | 37.0+ | Android 调试 |
| Python | 3.8+ | 服务器脚本 |
| IDA Pro | 7.0+ | 二进制分析 (可选) |
| 目标设备 | OPPO Find N2 | exploit 目标 |

> [!WARNING]
> 必须使用 NDK r29 的 `aarch64-linux-android35-clang`。使用其他版本可能导致 shadow stack OOM。

### 编译 exploit

```bash
cd exploit/
make NDK=/tmp/ndk_extract/android-ndk-r29   # 指定 NDK 路径
```

### 部署到设备

```bash
adb push preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

### 验证成功

成功标志：
- `[+] preload starting pid=...`
- `[*] parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (16)`
- `[*] pile-up verified: approx_time=...`
- `[*] prepare_kernel_page leaked_mm=...`

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
├── 问题描述.md                         # 完整问题描述
├── exploit/                           # exploit 源代码与构建
│   ├── Makefile                       # 构建脚本
│   ├── src/                           # 源代码
│   │   ├── main.c                     # 主入口
│   │   ├── util.c                     # KernelSnitch 设置与工具函数
│   │   ├── slide.c                    # KASLR bypass (pselect)
│   │   ├── fops.c                     # file_operations 利用
│   │   ├── pipe.c                     # pipe 物理读写
│   │   ├── root.c                     # root 提权
│   │   ├── preload.c                  # LD_PRELOAD 入口
│   │   ├── su_blob.S                  # su 二进制嵌入
│   │   ├── wallpaper_blob.S           # wallpaper 嵌入
│   │   ├── common.h                   # 公共定义与偏移
│   │   └── kernelsnitch/              # KernelSnitch 库
│   │       ├── kernelsnitch.h         # 核心逻辑
│   │       ├── futex_hash.h           # Jenkins jhash2
│   │       ├── timeutils.h            # ARM cntvct_el0 计时
│   │       └── utils.h                # 工具函数
│   ├── targets/oppo-find_n2/          # 设备特定配置
│   │   └── target.h                   # 内核偏移量 (IDA 验证)
│   └── test-programs/                 # 测试程序
├── analysis-scripts/                  # 分析脚本
├── docs/                              # 文档
│   ├── architecture.md                # 架构设计
│   ├── setup.md                       # 环境搭建
│   ├── best-practice.md               # 最佳实践
│   ├── knowledge-notes.md             # 技术知识沉淀
│   ├── adaptation-guide.md            # 适配指南
│   └── pr13-analysis.md              # PR #13 分析报告
└── kernel.elf                         # 分析用内核二进制
```

## 文档导航

| 文档 | 说明 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI Agent 指南 |
| [HANDOFF.md](HANDOFF.md) | 会话交接文档 |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 问题排查手册 |
| [FAQ.md](FAQ.md) | 常见问题 |
| [CHANGELOG.md](CHANGELOG.md) | 版本更新日志 |
| [架构设计](docs/architecture.md) | exploit 架构设计 |
| [环境搭建](docs/setup.md) | 开发环境搭建 |
| [最佳实践](docs/best-practice.md) | 开发最佳实践 |
| [技术知识](docs/knowledge-notes.md) | 技术知识沉淀 |
| [适配指南](docs/adaptation-guide.md) | GhostLock 适配指南 |
| [PR #13 分析](docs/pr13-analysis.md) | PR #13 bypass slide 分析 |

## 已验证的关键地址 (IDA output.elf)

| 符号 | 地址 | 偏移 |
|------|------|------|
| ashmem_fops | 0xffffffc00a2c0048 | 0x02c0048 |
| configfs_bin_file_operations | 0xffffffc00a175920 | 0x0175920 |
| init_task | 0xffffffc00a7cc000 | 0x027cc000 |
| kmalloc_caches | 0xffffffc00a302060 | 0x02302060 |
| selinux_state | 0xffffffc00aa793c8 | 0x02a793c8 |
| anon_pipe_buf_ops | 0xffffffc00a16aa68 | 0x0216aa68 |

## 参考资料

- [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — 原始 exploit 项目
- [GhostLock CVE-2026-43499](https://nebusec.ai/research/ionstack-part-2/) — 内核漏洞分析
- [IonStack Part I](https://nebusec.ai/research/ionstack-part-1/) — Firefox 漏洞分析
- [CyberMeowfia PoC](https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c) — PoC 代码
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — 内核符号提取工具
- [Dere3046 Expert Analysis](https://github.com/NebuSec/CyberMeowfia/pull/22) — K80U PR #22 适配建议

## 开源协议

本项目采用 [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0) 开源协议。

## 免责声明

本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。
