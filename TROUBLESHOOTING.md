# TROUBLESHOOTING.md

# 问题排查手册

## 文档说明

本文档收录 OPPO Find N2 GhostLock exploit 开发过程中遇到的所有问题及其解决方案。问题按类型分类，每条问题包含触发场景、报错信息、排查思路和解决方案。

## 问题分类归档

### 构建编译类

#### 1. 编译找不到 NDK

**问题标题**: NDK 路径未找到

**触发场景**: 执行 `make NDK=...` 时

**完整报错信息**:
```
/Users/xiuxiu391/Desktop/oppo/oppo-ghostlock/exploit/Makefile:34: *** "NDK not found". Stop.
```

**复现步骤**:
1. 未设置 NDK 环境变量
2. 执行 `make`

**排查思路**:
1. 检查 NDK 是否已安装
2. 检查路径是否正确
3. macOS 路径与 Linux 不同

**解决方案**:
- 临时规避: `export NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK`
- 最终修复: 在 Makefile 中指定正确路径

**根因分析**: NDK 安装路径在 macOS 和 Linux 上不同，Makefile 硬编码了 `linux-x86_64`。

**规避建议**: 编译前始终设置 `NDK` 环境变量。

---

#### 2. shadow stack OOM

**问题标题**: android35 编译导致 shadow stack OOM

**触发场景**: 使用 `aarch64-linux-android35-clang` 编译

**完整报错信息**:
```
ld.lld: error: shadow stack AArch64 support is not implemented for this platform
```

**复现步骤**:
1. 使用 android35 API 编译
2. 链接阶段失败

**排查思路**:
1. 检查 API level
2. 尝试不同 API level

**解决方案**:
- 临时规避: 使用 android34 或更低版本
- 最终修复: 使用 android35 但设置特定链接选项

**根因分析**: NDK r29 的 android35 API 对 shadow stack 支持不完整。

**规避建议**: 使用 `aarch64-linux-android35-clang` 时注意 shadow stack 限制。

---

#### 3. target.h 缺失

**问题标题**: TARGET_CONFIG_H 未定义

**触发场景**: 编译时未指定 `-DTARGET_CONFIG_H`

**完整报错信息**:
```
error: 'TARGET_CONFIG_H' undeclared
```

**复现步骤**:
1. 编译时未传递 `-DTARGET_CONFIG_H`
2. 编译失败

**排查思路**:
1. 检查 Makefile 是否传递了 `-D` 参数
2. 检查 target.h 路径

**解决方案**:
- 临时规避: 手动添加 `-DTARGET_CONFIG_H='"targets/oppo-find_n2/target.h"'`
- 最终修复: 在 Makefile 中配置

**根因分析**: `TARGET_CONFIG_H` 是编译时必需的宏定义，用于指定设备特定的偏移量。

**规避建议**: 编译时始终确保 `TARGET_CONFIG_H` 已定义。

---

### 运行时异常类

#### 4. KernelSnitch mm_struct 泄漏失败

**问题标题**: mm_struct 地址泄漏返回 0

**触发场景**: 运行 KernelSnitch standalone 测试

**完整报错信息**:
```
[*] KernelSnitch leaked mm_struct = 0000000000000000
[-] could not find valid owner in mm_struct
```

**复现步骤**:
1. 编译 `test_ks.c`
2. 推送到设备运行
3. 输出 mm_struct = 0

**排查思路**:
1. 检查 IDENTITY range 是否正确
2. 检查 MM_STRUCT_SZ 是否匹配
3. 检查 hashsize 对齐

**解决方案**:
- 临时规避: 无
- 最终修复: 应用 7-bug 修复 (IDENTITY range, KSNITCH_COLLISIONS, MM_STRUCT_SZ, hashsize, pile-up, futex_hash, nr_cpu_ids)

**根因分析**: 多个参数不匹配导致 hash timing 无法正确检测冲突。

**规避建议**: 确保所有 KernelSnitch 参数与目标设备匹配。

---

#### 5. route_done crash

**问题标题**: GhostLock 触发后内核 crash

**触发场景**: 运行 GhostLock exploit

**完整报错信息**:
```
[  123.456789] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
```

**复现步骤**:
1. 编译 exploit
2. 推送到设备运行
3. 内核 crash

**排查思路**:
1. 检查 kaslr_base 是否正确
2. 检查 text_addr() 计算
3. 检查 fake fops 函数指针

**解决方案**:
- 临时规避: 无
- 最终修复: 修复 kaslr_base/text_addr 架构性错误 (直接映射地址 vs 内核文本基地址)

**根因分析**: `kaslr_base` 被错误设为直接映射地址，但 `text_addr()` 期望内核文本基地址，导致 fake fops 中所有函数指针错误。

**规避建议**: 使用 `leak_kernel_base()` 正确计算 kaslr_base。

---

#### 6. pselect 内核死锁

**问题标题**: pselect fd_set 栈覆盖导致内核死锁

**触发场景**: NFDS > 336 时调用 pselect

**完整报错信息**:
```
[  456.789012] INFO: task xxx:1234 blocked for more than 120 seconds.
```

**复现步骤**:
1. 设置 NFDS > 336
2. 调用 pselect
3. 内核死锁

**排查思路**:
1. 检查 fd_set 是否在堆上
2. 检查 waiter 是否被覆盖
3. 检查 PI chain 是否正常

**解决方案**:
- 临时规避: 使用 NFDS ≤ 336
- 最终修复: 放弃 pselect fd_set 栈覆盖 (架构性死路)

**根因分析**: NFDS > 336 时 fd_set 在堆上，waiter 未被覆盖，PI 遍历读到无效 lock 指针。

**规避建议**: 不要在 OPPO Find N2 上使用 pselect fd_set 栈覆盖。

---

### 功能异常类

#### 7. configfs read_once 返回 EOF

**问题标题**: ashmem configfs 页面映射未创建

**触发场景**: 调用 `configfs_read_once()`

**完整报错信息**:
```
configfs_read_once: pread returned 0 (errno=0)
```

**复现步骤**:
1. 调用 `configfs_read_once()`
2. pread 返回 0

**排查思路**:
1. 检查 ashmem 设备是否存在
2. 检查 configfs 是否挂载
3. 检查内核配置

**解决方案**:
- 临时规避: 无
- 最终修复: 放弃 pipe physrw (依赖 configfs)

**根因分析**: OPPO 内核的 ashmem 驱动没有 configfs 支持，`CONFIG_ASHMEM_CONFIGFS` 未启用。

**规避建议**: 不要在 OPPO Find N2 上依赖 configfs R/W。

---

#### 8. CVE-2026-23274 触发失败

**问题标题**: IDLETIMER UAF 无法触发

**触发场景**: 调用 `setsockopt(IPT_SO_SET_REPLACE)`

**完整报错信息**:
```
setsockopt: Operation not permitted (errno=1)
```

**复现步骤**:
1. 创建 AF_INET SOCK_RAW socket
2. 调用 setsockopt
3. 权限被拒绝

**排查思路**:
1. 检查 CAP_NET_RAW
2. 检查 SELinux 策略
3. 检查 CONFIG_USER_NS

**解决方案**:
- 临时规避: 无
- 最终修复: 放弃 CVE-2026-23274 (需要 CAP_NET_RAW)

**根因分析**: 漏洞触发链每一步都需要 CAP_NET_RAW，而设备无 root + CONFIG_USER_NS=n。

**规避建议**: 不要在无 root 环境下尝试 IDLETIMER UAF。

---

### 环境搭建类

#### 9. 设备无 root

**问题标题**: 无法获取 root 权限

**触发场景**: 尝试 `adb root` 或 `su`

**完整报错信息**:
```
adbd cannot run as root in production builds
```

**复现步骤**:
1. 执行 `adb root`
2. 失败

**排查思路**:
1. 检查设备是否已 root
2. 检查 boot image 是否已修改
3. 检查 Magisk 是否安装

**解决方案**:
- 临时规避: 无
- 最终修复: 接受无 root 环境，寻找不需要 root 的利用路径

**根因分析**: OPPO Find N2 是 production build，不支持 root。

**规避建议**: 所有 exploit 必须在无 root 环境下工作。

---

#### 10. SELinux Enforcing

**问题标题**: SELinux 阻止内核攻击面

**触发场景**: 尝试 BPF/ashmem/userfaultfd 操作

**完整报错信息**:
```
avc: denied { read } for ... scontext=u:r:shell:s0 tcontext=... tclass=...
```

**复现步骤**:
1. 尝试 BPF_MAP_CREATE
2. SELinux deny

**排查思路**:
1. 检查 SELinux 状态
2. 检查 shell 域策略

**解决方案**:
- 临时规避: 无
- 最终修复: 接受 SELinux 限制，寻找不需要这些操作的利用路径

**根因分析**: shell 域 (u:r:shell:s0) 没有 BPF/ashmem/userfaultfd 权限。

**规避建议**: 不要在 shell 域下尝试这些操作。
