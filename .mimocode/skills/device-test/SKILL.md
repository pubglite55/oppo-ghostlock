---
name: device-test
description: 编译并运行测试程序到 Android 设备
---

# Device Test

编译测试程序并部署到 Android 设备运行。

## 使用时机

- 测试新的漏洞利用方法
- 验证内核信息泄漏
- 测试时序攻击

## 步骤

### 1. 编译测试程序

```bash
cd /Users/xiuxiu391/Desktop/oppo/oppo-ghostlock

NDK=/tmp/ndk_extract/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang
SYSROOT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot

$CC --target=aarch64-linux-android35 --sysroot=$SYSROOT \
  -O2 test-programs/test_xxx.c -o test_xxx
```

### 2. 部署到设备

```bash
adb push test_xxx /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/test_xxx"
```

### 3. 运行测试

```bash
adb shell "/data/local/tmp/test_xxx"
```

### 4. 分析结果

查看输出，分析：
- 时序测量值
- 信息泄漏
- 错误信息

## 测试程序列表

| 程序 | 用途 |
|------|------|
| test_futex.c | FUTEX PI 操作测试 |
| test_binder.c | binder ioctl 测试 |
| test_pselect_nfds.c | pselect NFDS 测试 |
| test_reclaim.c | stack reclaim 方法测试 |
| test_seccomp_futex.c | seccomp + futex 测试 |
| test_leak_mm.c | mm_struct 泄漏方法测试 |
| test_kernel_leak.c | 内核信息泄漏测试 |
| test_cache_timing.c | Cache-based 时序攻击测试 |
| test_improved_timing.c | 改进时序测量测试 |
| test_auxv_leak.c | 辅助向量泄漏测试 |

## 注意事项

- 测试程序可能需要 root 权限
- 某些测试可能需要特定设备配置
- 测试失败可能导致设备重启
