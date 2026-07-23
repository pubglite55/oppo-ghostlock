# oppo-ghostlock

GhostLock CVE-2026-43499 — OPPO Find N2 Linux 内核提权研究

[![Version](https://img.shields.io/badge/version-1.0--research-blue)](https://github.com/pubglite55/oppo-ghostlock)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 项目概述

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 至 7.1-rc1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞态条件触发。本项目将 NebuSec/CyberMeowfia 的 x86_64 exploit 适配到 OPPO Find N2 (ARM64, kernel 5.10.236)。

## 项目状态

**迭代中** — 多个利用阶段已验证通过，但核心阻塞点（CFI bypass / 内核写原语）尚未突破。

## 核心特性

- Firefox CVE-2026-10702 exploit — SpiderMonkey type confusion → AAW
- KernelSnitch mm_struct 泄漏 — futex hash timing 泄漏内核地址
- GhostLock FUTEX 触发 — `FUTEX_CMP_REQUEUE_PI` ret=0
- sk_buff 堆喷射 — 4/4 send 成功
- PR #13 KASLR bypass — 直接计算 kaslr_base
- IDA Pro 全量偏移验证 — 70+ 内核偏移通过验证

## 快速开始

### 环境要求

- macOS / Linux (需要 Android NDK)
- Android NDK r29
- OPPO Find N2 设备

### 编译部署

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

# 5. 运行
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## 仓库结构

```
oppo-ghostlock/
├── exploit/
│   ├── src/
│   │   ├── main.c              # 主入口，GhostLock 触发
│   │   ├── fops.c              # pselect fake lock + kernel base leak
│   │   ├── pipe.c              # pipe 物理读写
│   │   ├── root.c              # root 提权
│   │   ├── util.c              # 工具函数
│   │   └── kernelsnitch/       # mm_struct 泄漏
│   ├── targets/                # 设备偏移定义
│   └── Makefile
└── README.md
```

## 设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_FUTEX_PI=y**
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced**

## 核心阻塞

1. pselect 无法操纵 waiter 结构 — NFDS > 336 时 fd_set 在堆上
2. configfs/ashmem 不支持 — ashmem SET_NAME 被截断
3. 所有其他内核写入路径被阻塞 — /proc/self/mem, /dev/mem, binder

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

## 致谢

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — GhostLock exploit 原始实现
- [NebuSec IonStack Writeup](https://nebusec.ai/research/ionstack-part-2/) — GhostLock 技术分析
- [Dere3046/ElevateMe](https://github.com/Dere3046/ElevateMe) — rb_erase cred 覆写机制
