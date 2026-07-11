# 问题排查手册

## 文档说明

本文档收录了在 GhostLock OPPO Find N2 exploit 开发和测试过程中遇到的所有问题及其解决方案。

**检索方式**: 按问题类型分类，每类下按出现频率排序
**使用建议**: 遇到问题时先搜索关键词，找到对应问题后按步骤排查

---

## 环境搭建类

### 1. Android NDK 安装失败

**触发场景**: 下载 NDK 时网络超时
**报错信息**: 连接超时或下载中断
**解决方案**: 使用 Homebrew 安装
```bash
brew install --cask android-ndk
```

### 2. NDK 路径不匹配

**触发场景**: 编译时报错找不到编译器
**报错信息**: `No such file or directory: /tmp/ndk_extract/android-ndk-r29/...`
**解决方案**: 创建符号链接
```bash
mkdir -p /tmp/ndk_extract
ln -sf ~/Library/Android/android-ndk-r29 /tmp/ndk_extract/android-ndk-r29
```

---

## 构建/编译报错类

### 3. 缺少嵌入文件 (su_daemon, wallpaper.webp)

**触发场景**: 编译 exploit 时
**报错信息**:
```
src/su_blob.S:7:9: error: Could not find incbin file 'build/embed/su_daemon_aarch64_pie'
src/wallpaper_blob.S:6:9: error: Could not find incbin file 'assets/wallpaper.webp'
```
**解决方案**:
```bash
cd exploit
mkdir -p build/embed assets

# 编译 su_daemon
$CC --target=aarch64-linux-android35 --sysroot=$SYSROOT -O2 -pie \
  src/su_daemon.c -o build/embed/su_daemon_aarch64_pie

# 创建 wallpaper 占位文件
python3 -c "
import struct
data = b'RIFF' + struct.pack('<I', 0) + b'WEBP'
data += b'VP8 ' + struct.pack('<I', 30)
data += bytes([0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00])
data += bytes([0x01, 0x40, 0x25, 0xa4, 0x00, 0x03, 0x70, 0x00])
data += bytes([0xfe, 0xfb, 0x94, 0x00, 0x00])
size = len(data) - 8
data = data[:4] + struct.pack('<I', size) + data[8:]
open('assets/wallpaper.webp', 'wb').write(data)
"
```

### 4. TARGET_CONFIG_H 未定义

**触发场景**: 编译 exploit 时
**报错信息**:
```
src/offset.h:1:10: error: "TARGET_CONFIG_H is not defined"
```
**解决方案**: 编译时添加 `-DTARGET_CONFIG_H` 定义
```bash
$CC ... -DTARGET_CONFIG_H='"targets/oppo-find_n2/target.h"' ...
```

### 5. PMCCNTR_EL0 访问失败

**触发场景**: 修改 timeutils.h 使用性能监控计数器
**报错信息**: KernelSnitch 碰撞查找失败，assert 错误
**解决方案**: 恢复使用 cntvct_el0 (用户态无法访问 PMCCNTR_EL0)
```c
// 恢复原始代码
#elif defined(__ARM)
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
```

---

## 运行时异常类

### 6. KernelSnitch mm_struct 泄漏失败

**触发场景**: 运行 exploit 时
**报错信息**:
```
[-] KernelSnitch mm_struct leak failed
[-] prepare_kernel_page retry 1/12
```
**排查思路**:
1. 检查 MM_STRUCT_SZ 是否正确 (应为 0x3c0)
2. 检查 MM_ORDER 是否正确 (应为 3)
3. 检查 futex_hashsize 是否正确 (应为 2048)
4. 检查 KPTI 是否启用
**解决方案**: 当前无解决方案，等待 NebuSec Android blog
**根因分析**: KPTI 启用导致时序侧信道不准确，cntvct_el0 精度不足

### 7. FUTEX_WAIT_REQUEUE_PI 超时

**触发场景**: GhostLock 触发阶段
**报错信息**:
```
slide waiter FUTEX_WAIT_REQUEUE_PI returned ret=-1 errno=110
slide waiter: FUTEX_WAIT_REQUEUE_PI timed out
```
**排查思路**:
1. 检查线程同步是否正确
2. 检查 futex 地址是否有效
**解决方案**: 这是预期行为，GhostLock 需要超时才能触发
**根因分析**: FUTEX_WAIT_REQUEUE_PI 超时是 GhostLock 触发的必要条件

### 8. 偏移不正确导致手机崩溃

**触发场景**: 使用错误偏移运行 exploit
**报错信息**: 手机重启
**排查思路**:
1. 对比 pahole 输出和 target.h
2. 检查 MM_STRUCT_SZ 和 MM_ORDER
3. 检查帧大小是否正确
**解决方案**: 使用 pahole 和 objdump 从 vmlinux 验证所有偏移
**根因分析**: 编译的内核与手机内核配置不同导致偏移差异

### 9. boot_id 不是内核指针

**触发场景**: slide.c 读取 /proc/sys/kernel/random/boot_id
**报错信息**:
```
slide boot_id does not look like kernel pointer=3246fd5f535124e2
slide: GhostLock may not have triggered, or stack reclaim failed
```
**排查思路**:
1. 检查 GhostLock 是否成功触发
2. 检查 stack reclaim 是否成功
**解决方案**: 当前无解决方案，需要先完成 stack reclaim
**根因分析**: boot_id 是 UUID 格式，只有 GhostLock 成功触发后才会被内核指针覆盖

---

## 功能异常类

### 10. /proc/kallsyms 全零

**触发场景**: 尝试读取内核符号地址
**报错信息**: 所有地址显示为 0000000000000000
**排查思路**:
1. 检查 kptr_restrict 值
2. 检查是否有 root 权限
**解决方案**: 需要 root 权限或等待 NebuSec 替代方法
**根因分析**: Android 安全机制限制内核信息泄漏

### 11. ASHMEM 权限拒绝

**触发场景**: 尝试打开 /dev/ashmem
**报错信息**: `Permission denied`
**解决方案**: 需要 root 权限
**根因分析**: Android SELinux 策略限制

### 12. userfaultfd 不允许

**触发场景**: 尝试创建 userfaultfd
**报错信息**: `Operation not permitted (errno=1)`
**解决方案**: 需要 root 权限
**根因分析**: Android seccomp 限制

---

## 性能问题类

### 13. KernelSnitch 暴力搜索耗时过长

**触发场景**: exploit 运行缓慢
**排查思路**:
1. 检查 CPU 核心数
2. 检查线程数配置
**解决方案**: 确保使用多核并行搜索
```c
int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
// 通常 8 核设备会创建 8 个搜索线程
```

### 14. fork 时序精度不足

**触发场景**: 测试 fork 时序泄漏 mm_struct
**报错信息**: 1077μs/次，无法检测时序差异
**解决方案**: fork 时序方法不适用，需要其他方法
**根因分析**: fork 操作本身耗时太长，无法用于精密时序测量
