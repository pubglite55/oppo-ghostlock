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
| IDA 偏移验证 | ✅ 完成 | output.elf 双重验证 |
| GhostLock FUTEX PI 触发 | ✅ **验证成功** | FUTEX_CMP_REQUEUE_PI ret=1 |
| C ashmem 类型验证 | ✅ 完成 | ashmem_area 312 bytes, name[88] 重叠 |
| configfs_bin_file_operations | ✅ 找到 | bin_buffer at offset +88 |
| **mm_struct 地址泄漏** | ❌ **阻塞** | KPTI 导致所有时序方法失败 |
| **覆盖 ashmem_misc.fops** | ❌ **阻塞** | 依赖 mm_struct 地址 |
| 类型混淆 (任意读写) | ⏳ 待实现 | 依赖 fops 覆盖 |
| 提权 (cred + SELinux) | ⏳ 待实现 | 依赖任意读写 |

### 核心阻塞问题

**需要 mm_struct 地址** 来布置 fake kernel page，从而覆盖 `ashmem_misc.fops` 指向 `configfs_bin_file_operations`。没有 mm_struct 地址，类型混淆无法启动。

详见 [问题描述](问题描述.md) 和 [适配分析](docs/adaptation-guide.md)。

## 核心特性

- **GhostLock 触发验证** — 通过 `FUTEX_CMP_REQUEUE_PI` 成功触发 GhostLock 漏洞，requeue ret=1
- **C ashmem 类型混淆** — 验证 OPPO Find N2 使用 C ashmem，`name[88]` 与 `configfs_buffer.bin_buffer` 重叠
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
cd exploit/

# 使用 Makefile (推荐)
make                    # 自动检测 NDK
make NDK=/path/to/ndk  # 指定 NDK 路径
```

### 部署到设备

```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### 验证成功

成功后会显示:

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
├── 问题描述.md                        # 完整问题描述 (发给大佬求助)
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
│   ├── targets/oppo-find_n2/          # 设备特定配置
│   │   └── target.h                   # 内核偏移量 (IDA 验证)
│   └── test-programs/                 # 测试程序
├── analysis-scripts/                  # 分析脚本
├── docs/                              # 文档
│   ├── architecture.md                # 架构设计
│   ├── setup.md                       # 环境搭建
│   ├── best-practice.md               # 最佳实践
│   ├── knowledge-notes.md             # 技术知识沉淀
│   └── adaptation-guide.md            # 适配指南
├── test-programs/                     # 测试程序
├── extract-vmlinux                    # vmlinux 提取工具
└── kernel.elf                         # 分析用内核二进制
```

## 文档导航

| 文档 | 说明 |
|------|------|
| [问题描述](问题描述.md) | 完整问题描述 (发给大佬求助) |
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

## 免责声明

本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。

## License

GPL License
