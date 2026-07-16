# README.md

# oppo-ghostlock

GhostLock CVE-2026-43499 — OPPO Find N2 Linux 内核提权研究

[![Version](https://img.shields.io/badge/version-1.0--research-blue)](https://github.com/pubglite55/oppo-ghostlock)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-NDK%20r29-orange)]()

## 项目概述

### 项目背景

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 至 7.1-rc1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞态条件触发。本项目旨在将 NebuSec/CyberMeowfia 的 x86_64 exploit 适配到 OPPO Find N2 (ARM64, kernel 5.10.236)，实现无 root 环境下的内核提权。

### 核心痛点

- GhostLock exploit 原始实现基于 x86_64 架构，无法直接在 ARM64 设备上运行
- OPPO Find N2 内核安全配置极其严格，所有已知利用路径均被阻塞
- 缺少 root 权限和 user namespaces，无法触发需要特权的漏洞

### 适用场景

- Linux 内核安全研究与漏洞验证
- ARM64 架构 exploit 适配参考
- GhostLock (CVE-2026-43499) 漏洞利用链分析
- Android 设备内核安全评估

### 当前项目状态

**迭代中** — 多个利用阶段已验证通过，但核心阻塞点（CFI bypass / 内核写原语）尚未突破。

## 核心特性

- **Firefox CVE-2026-10702 exploit** — SpiderMonkey type confusion → AAW，已在设备上验证
- **KernelSnitch mm_struct 泄漏** — 通过 futex hash timing 泄漏内核地址，7-bug 修复已验证
- **GhostLock FUTEX 触发** — `FUTEX_CMP_REQUEUE_PI` ret=0，触发成功
- **sk_buff 堆喷射** — 4/4 send 成功，可用于堆布局控制
- **PR #13 KASLR bypass** — 绕过 slide，直接计算 kaslr_base
- **IDA Pro 全量偏移验证** — 70+ 内核偏移通过 output.elf 验证

## 技术栈全景

### 运行时层
- Android 16 (BP2A.250605.015)
- Linux kernel 5.10.236-android12-9-o-g74d132f4467a
- OPPO Find N2 (SM8475/CPH2413)

### 核心机制层
- GhostLock (CVE-2026-43499) rtmutex stack UAF
- FUTEX_CMP_REQUEUE_PI 竞态触发
- KernelSnitch futex hash timing 泄漏
- pselect fd_set 栈覆盖 / 堆喷射

### 工具链层
- Android NDK r29 (`aarch64-linux-android35-clang`)
- IDA Pro (output.elf.i64, MCP port 13337)
- pahole (结构体偏移验证)
- adb (设备调试)

### 依赖库层
- NebuSec/CyberMeowfia exploit 框架
- Firefox 151 (CVE-2026-10702)

## 快速开始

### 环境要求

- macOS / Linux (需要 Android NDK)
- Android NDK r29
- OPPO Find N2 设备 (serial=84cb96e2)
- Firefox 151 (用于 Stage 1)

### 安装部署

```bash
# 1. 克隆仓库
git clone https://github.com/pubglite55/oppo-ghostlock.git
cd oppo-ghostlock

# 2. 设置 NDK 路径
export NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 3. 编译 exploit
cd exploit/
make clean && make NDK=$NDK

# 4. 推送到设备
adb push preload.so /data/local/tmp/
```

### 启动运行

```bash
# 运行 exploit
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1

# 验证成功: 输出 "preload starting pid=..." 表示加载成功
```

### 最简使用示例

```bash
# 编译
cd exploit/ && make clean && make NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 部署
adb push preload.so /data/local/tmp/

# 运行
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## 仓库目录结构

```
oppo-ghostlock/
├── exploit/                          # 核心 exploit 代码
│   ├── src/
│   │   ├── main.c                    # 主入口，GhostLock 触发
│   │   ├── fops.c                    # pselect fake lock route + kernel base leak
│   │   ├── pipe.c                    # pipe 物理读写
│   │   ├── root.c                    # root 提权
│   │   ├── slide.c                   # KASLR bypass (已弃用)
│   │   ├── util.c                    # 工具函数 (text_addr, configfs)
│   │   ├── kernelsnitch/             # KernelSnitch mm_struct 泄漏
│   │   │   ├── kernelsnitch.h        # KernelSnitch 头文件
│   │   │   └── futex_hash.h          # futex hash 修复
│   │   └── targets/
│   │       └── oppo-find_n2/
│   │           └── target.h          # OPPO Find N2 偏移量定义
│   ├── Makefile                      # 编译脚本
│   └── out/                          # 编译输出
├── docs/                             # 文档目录
│   ├── architecture.md               # 架构设计文档
│   ├── setup.md                      # 环境搭建文档
│   ├── best-practice.md              # 开发最佳实践
│   └── knowledge-notes.md            # 技术知识沉淀
├── test-programs/                    # 测试程序
├── analysis-scripts/                 # 分析脚本
├── AGENTS.md                         # 智能体说明
├── TESTED_METHODS.md                 # 所有测试方法汇总
├── TROUBLESHOOTING.md                # 问题排查手册
├── FAQ.md                            # 常见问题
├── CHANGELOG.md                      # 版本更新日志
├── handoff.md                        # 项目交接文档
├── 问题描述.md                        # 项目问题梳理
└── README.md                         # 本文件
```

## 文档导航

- [架构设计文档](docs/architecture.md) — exploit chain 设计与实现
- [环境搭建文档](docs/setup.md) — 开发环境配置与部署
- [开发最佳实践](docs/best-practice.md) — 代码规范与核心原理
- [技术知识沉淀](docs/knowledge-notes.md) — 内核结构体与漏洞机制
- [问题排查手册](TROUBLESHOOTING.md) — 全量问题排查指南
- [常见问题](FAQ.md) — 高频问题速查
- [版本更新日志](CHANGELOG.md) — 项目迭代记录
- [项目交接文档](handoff.md) — 标准交接文档
- [智能体说明](AGENTS.md) — 智能体指令文档
- [所有测试方法](TESTED_METHODS.md) — 56+ 方法完整记录
- [项目问题梳理](问题描述.md) — 问题清单与状态

## 开源协议

本项目采用 MIT 协议。

## 致谢/参考

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — GhostLock exploit 原始实现
- [NebuSec IonStack Writeup](https://nebusec.ai/research/ionstack-part-2/) — GhostLock 技术分析
- [Dere3046/ElevateMe](https://github.com/Dere3046/ElevateMe) — rb_erase cred 覆写机制
- 52pojie OnePlus 13T 适配帖 — 偏移分类方法论
- brszzz.github.io 技术博客 — 内核符号还原方法
