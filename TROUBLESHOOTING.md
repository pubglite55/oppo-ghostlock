# 问题排查手册

## 文档说明

本文档收录了在 GhostLock OPPO Find N2 exploit 开发和测试过程中遇到的所有问题及其解决方案。

**检索方式**: 按问题类型分类，每类下按出现频率排序
**使用建议**: 遇到问题时先搜索关键词，找到对应问题后按步骤排查

---

## 环境搭建类

### 1. Homebrew 无法以 root 运行

**触发场景**: 在 root 用户下执行 `brew install`
**报错信息**:
```
Running Homebrew as root is extremely dangerous and no longer supported.
```
**解决方案**: 创建普通用户或使用其他包管理器
```bash
# 方案1: 创建普通用户
useradd -m builder
su - builder -c "brew install ..."

# 方案2: 使用 apt (Linux)
sudo apt install gcc-11 make flex bison libssl-dev bc libelf-dev dwarves
```

### 2. Android NDK 下载失败

**触发场景**: 下载 NDK 时网络超时
**报错信息**: 连接超时或下载中断
**解决方案**: 使用镜像源或手动下载
```bash
# 使用 Google 镜像
wget https://dl.google.com/android/repository/android-ndk-r29-darwin.zip

# 或使用代理
export https_proxy=http://proxy:port
```

---

## 依赖安装类

### 3. aarch64-linux-gnu-gcc 找不到

**触发场景**: `apt install` 时包名错误
**报错信息**:
```
E: Unable to locate package aarch64-linux-gnu-gcc
```
**解决方案**: 使用正确的包名
```bash
# 正确的包名
sudo apt install gcc-aarch64-linux-gnu
```

### 4. pahole 安装失败

**触发场景**: macOS 上安装 dwarves
**报错信息**: `No available formula with the name "dwarves"`
**解决方案**: 使用 pyelftools 作为替代
```bash
pip3 install pyelftools
```

---

## 构建/编译报错类

### 5. OPLUS 内核编译失败 - 缺失 vendor/o

**触发场景**: 编译 OPPO 内核源码
**报错信息**:
```
can't open file "kernel/oplus_cpu/sched/Kconfig"
```
**复现步骤**:
```bash
cd android_kernel_oppo_sm8475-*
make gki_defconfig
```
**解决方案**:
```bash
# 1. 下载模块仓库
wget https://github.com/oppo-source/android_kernel_modules_and_devicetree_oppo_sm8475/archive/refs/heads/oppo/sm8475_b_16.0.0_find_n2.zip

# 2. 解压并复制 vendor/o
unzip android_kernel_modules_and_devicetree_oppo_sm8475-*.zip
cp -r android_kernel_modules_and_devicetree_oppo_sm8475-*/vendor/oplus \
  android_kernel_oppo_sm8475-*/vendor/
```
**根因分析**: OPPO 内核源码不完整，vendor 目录在单独的模块仓库中

### 6. 内核编译 forbidden warning

**触发场景**: 编译内核时出现警告
**报错信息**:
```
error, forbidden warning: kern_levels.h:5:25
```
**解决方案**:
```bash
# 修改 cc-wrapper.c 禁用警告检查
sed -i "s/ret = 1;/ret = 0;/" scripts/basic/cc-wrapper.c
```
**根因分析**: OPLUS 内核的 cc-wrapper.c 会将警告视为错误

### 7. 缺失 Kconfig 文件

**触发场景**: `make gki_defconfig` 时报错
**报错信息**:
```
can't open file "kernel/sched/walt/tuning/Kconfig"
```
**解决方案**: 自动创建缺失的 Kconfig
```bash
for i in $(seq 1 30); do
  make gki_defconfig 2>&1 | grep "can.t open file" | \
    sed 's/.*can.t open file .\(.*\)/\1/' | while read f; do
      mkdir -p "$(dirname "$f")"
      touch "$f"
    done
done
```

### 8. CONFIG_WERROR 导致编译失败

**触发场景**: 使用手机的 .config 编译内核
**报错信息**:
```
cc1: all warnings being treated as errors
```
**解决方案**:
```bash
sed -i "s/CONFIG_WERROR=y/# CONFIG_WERROR is not set/" .config
```

---

## 运行时异常类

### 9. KernelSnitch mm_struct leak failed

**触发场景**: 运行 exploit 时 KernelSnitch 失败
**报错信息**:
```
[-] KernelSnitch mm_struct leak failed
[-] prepare_kernel_page retry 1/12
```
**复现步骤**: 使用默认偏移运行 exploit
**排查思路**:
1. 检查 MM_STRUCT_SZ 是否正确
2. 检查 MM_ORDER 是否正确
3. 检查 Seccomp 状态
**解决方案**:
```c
// 修复 common.h 中的偏移
#define MM_STRUCT_SZ 0x3c0  // 960 bytes (包含 cpumask)
#define MM_ORDER 3          // SLUB slab order
```
**根因分析**: MM_STRUCT_SZ 原值 0x500 (1280) 不正确，实际应为 0x3c0 (960)
**规避建议**: 使用 pahole 从编译的 vmlinux 提取精确偏移

### 10. FUTEX_CMP_REQUEUE_PI 被 seccomp 阻止

**触发场景**: GhostLock 触发阶段
**报错信息**: 手机崩溃重启
**排查思路**:
1. 检查 Seccomp 状态: `Seccomp=2 Seccomp_filters=1`
2. 测试 FUTEX PI 操作是否被阻止
**解决方案**: 需要使用替代技术绕过 seccomp
**根因分析**: Firefox 的 seccomp 沙箱阻止了 FUTEX PI 操作

### 11. 偏移不正确导致手机崩溃

**触发场景**: 使用错误偏移运行 exploit
**报错信息**: 手机重启
**排查思路**:
1. 对比 pahole 输出和 target.h
2. 检查 MM_STRUCT_SZ 和 MM_ORDER
**解决方案**: 使用 pahole 从编译的 vmlinux 提取精确偏移
**根因分析**: 编译的内核与手机内核配置不同导致偏移差异

---

## 功能异常类

### 12. Firefox exploit 页面打不开

**触发场景**: 手机访问 exploit 页面
**报错信息**: 页面空白或无法加载
**排查思路**:
1. 检查服务器是否运行: `curl http://localhost:8080/`
2. 检查 IP 地址是否正确
3. 检查手机和电脑是否在同一网段
**解决方案**:
```bash
# 检查服务器
ps aux | grep "python3.*http.server"

# 检查 IP
ifconfig en0 | grep inet
adb shell ip addr show wlan0 | grep inet

# 重启服务器
pkill -f "python3.*http.server"
cd exploit-server && python3 -m http.server 8080 &
```

### 13. Firefox 152 无法使用 exploit

**触发场景**: 安装了 Firefox 152
**报错信息**: exploit 不触发
**解决方案**:
```bash
# 下载 Firefox 151
curl -L -o fenix-151.0.apk \
  "https://archive.mozilla.org/pub/fenix/releases/151.0/android/fenix-151.0-android-arm64-v8a/fenix-151.0.multi.android-arm64-v8a.apk"

# 降级安装
adb install -d fenix-151.0.apk
```
**根因分析**: CVE-2026-10702 漏洞仅存在于 Firefox 151 中

---

## 性能问题类

### 14. KernelSnitch 暴力搜索耗时过长

**触发场景**: exploit 运行缓慢
**排查思路**:
1. 检查 CPU 核心数
2. 检查线程数配置
**解决方案**: 确保使用多核并行搜索
```c
int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
// 通常 8 核设备会创建 8 个搜索线程
```
