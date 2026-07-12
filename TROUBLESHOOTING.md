# 问题排查手册

## 文档说明

本文档收录了 OPPO Find N2 GhostLock exploit 开发过程中遇到的所有问题及其解决方案。

**检索方式**: 按问题类型分类，每条问题包含触发场景、报错信息、排查思路和解决方案。

---

## 环境搭建类

### Q: NDK 路径找不到

**触发场景**: 运行 `make` 时提示 NDK 未找到

**完整报错**:
```
Error: NDK not found. Set NDK=/path/to/ndk or install Android NDK
```

**解决方案**:
```bash
# 方法 1: 设置环境变量
export NDK=/tmp/ndk_extract/android-ndk-r29

# 方法 2: 指定 NDK 路径
make NDK=/tmp/ndk_extract/android-ndk-r29
```

**根因**: Makefile 自动检测路径不包含用户自定义安装路径。

---

## 构建/编译报错类

### Q: 编译时 format specifier 警告

**触发场景**: 编译 exploit 时出现 format 警告

**完整报错**:
```
src/util.c:561:82: warning: format specifies type 'int' but the argument has type 'size_t'
```

**解决方案**: 这是一个无害的警告，不影响功能。可以忽略或修改 format specifier。

**根因**: `%d` 用于 `size_t` 类型参数，应使用 `%zu`。

---

## 运行时异常类

### Q: ashmem 打开失败 (EACCES)

**触发场景**: 尝试打开 `/dev/ashmem` 时被拒绝

**完整报错**:
```
无法打开 /dev/ashmem: errno=13 (Permission denied)
```

**解决方案**:
```bash
# 使用 UUID 后缀路径
ls /dev/ashmem*  # 找到可用的 UUID 路径
# 输出: /dev/ashmem874642ac-55fc-4f92-8d57-c514c4666592

# 在代码中使用
int fd = open("/dev/ashmem874642ac-55fc-4f92-8d57-c514c4666592", O_RDWR | O_CLOEXEC);
```

**根因**: SELinux 限制 shell 域访问 `ashmem_device` 类型，但 UUID 后缀路径使用 `ashmem_libcutils_device` 类型，shell 有权限访问。

---

### Q: FUTEX_CMP_REQUEUE_PI 返回 errno=35 (EAGAIN)

**触发场景**: GhostLock 触发测试中，requeue 操作失败

**完整报错**:
```
REQUEUE ret=-1 errno=35
```

**排查思路**:
1. 检查 waiter 是否真正阻塞在 FUTEX_WAIT_REQUEUE_PI
2. 检查 f_wait 值是否正确
3. 检查 f_pi_target 是否已被 owner 锁定

**解决方案**:
```c
// 增加等待时间，确保 waiter 真正阻塞在内核中
usleep(500000);  // 500ms → 3000ms
// 或
sleep(3);
```

**根因**: waiter 调用 FUTEX_WAIT_REQUEUE_PI 后，内核需要时间将其加入 futex hash table。如果主线程在 waiter 真正阻塞前调用 requeue，内核找不到 waiter，返回 EAGAIN。

**验证方法**: 在 requeue 前打印 f_wait 值，确认 waiter 已阻塞。

---

### Q: FUTEX_WAIT_REQUEUE_PI 返回值未打印

**触发场景**: GhostLock 测试中，waiter 线程未输出 FUTEX_WAIT_REQUEUE_PI 的返回值

**完整报错**: 无 (程序卡住)

**排查思路**:
1. 检查 waiter 线程是否被其他 futex 阻塞
2. 检查 f_pi_chain 是否被正确锁定
3. 检查 owner 线程是否已启动

**解决方案**: 确保 waiter 线程在调用 FUTEX_WAIT_REQUEUE_PI 前已完成 FUTEX_LOCK_PI。

**根因**: waiter 可能被 f_pi_chain 的 FUTEX_LOCK_PI 阻塞，无法执行后续操作。

---

### Q: perf_event_open 被 SELinux 阻止

**触发场景**: 尝试使用 perf_event_open 泄漏内核地址

**完整报错**:
```
perf_event_open (SOFTWARE) 失败: Permission denied (errno=13)
```

**解决方案**: 无直接解决方案。需要 root 权限或 SELinux permissive 模式。

**根因**: SELinux Enforcing 阻止 shell 域访问 perf_event 设备。

---

## 功能异常类

### Q: KernelSnitch mm_struct 泄漏失败

**触发场景**: exploit 启动后，KernelSnitch 无法泄漏 mm_struct 地址

**完整报错**:
```
[-] KernelSnitch mm_struct leak failed
[-] prepare_kernel_page retry 1/12
```

**排查思路**:
1. 检查 CONFIG_FUTEX_PI 是否启用
2. 检查 futex_hashsize 是否正确
3. 检查 CPU 核心数配置
4. 检查 FUTEX_WAKE_PRIVATE timing ratio

**解决方案**: 目前无直接解决方案。需要寻找替代 mm_struct 泄露方法。

**根因（已确认 2026-07-13）**: 
- Kernel 5.10 的 `FUTEX_WAKE_PRIVATE` with `val=0` 被优化为**不遍历 hash chain**，直接返回
- 诊断测试结果：4096 waiters 时 timing ratio 仅 1.0-1.5x，远低于 KernelSnitch 需要的 10x 阈值
- `FUTEX_CMP_REQUEUE_PI` timing ratio 1.4x（不够）
- `FUTEX_TRYLOCK_PI` timing ratio 1.7x（不够）
- 所有基于 futex timing 的碰撞检测在 kernel 5.10 上完全失效

---

### Q: pselect fd_set 在堆上而非栈上

**触发场景**: 分析 pselect 栈回收可行性时发现

**技术细节**:
- `set_fd_set()` 调用 `bitmap_alloc()` 分配堆内存
- fd_set 数据存储在堆上，不在内核栈上
- 即使帧大小匹配，用户数据也无法到达 waiter 位置

**结论**: pselect 方法在 OPPO Find N2 上不可行。

---

### Q: /proc/self/pagemap 返回全零

**触发场景**: 尝试通过 pagemap 泄漏物理页号

**完整报错**: 无 (返回全零)

**解决方案**: 无。Android 内核限制用户态访问物理页信息。

**根因**: Android 内核配置 `CONFIG_STRICT_DEVMEM=y` 或类似限制。

---

### Q: pselect side-channel 能否替代 KernelSnitch 定位 mm_struct？

**触发场景**: 寻找 KernelSnitch 的替代方案

**技术分析**:
- pselect side-channel 泄漏的是**内核栈上的数据**（nfulnl_logger 地址），用于 KASLR bypass
- mm_struct 在 **slab 分配器**中，不在内核栈上
- pselect 泄漏的数据中不包含 current->mm 指针
- 无法直接从 pselect 泄漏的数据推导出 mm_struct 地址

**结论**: pselect side-channel 不能直接替代 KernelSnitch 定位 mm_struct。需要寻找其他方法。

---

## 性能问题类

### Q: GhostLock 触发时序要求

**触发场景**: GhostLock 测试中 requeue 频繁失败

**技术细节**:
- waiter 调用 FUTEX_WAIT_REQUEUE_PI 后需要 ~3 秒才能真正阻塞
- 主线程需要在 waiter 阻塞后才能调用 FUTEX_CMP_REQUEUE_PI
- 太早调用会导致 EAGAIN，太晚会导致 waiter 超时

**解决方案**: 使用管道或事件进行同步，确保 waiter 已阻塞后再 requeue。

---

### Q: 内核符号地址不匹配

**触发场景**: target.h 中的偏移与实际内核不匹配

**排查思路**:
1. 使用 IDA 打开 output.elf
2. 搜索对应符号名
3. 验证地址偏移

**解决方案**: 使用 `vmlinux-to-elf` 或 IDA 验证所有偏移。

**根因**: 仓库中的偏移可能来自不同的内核版本或编译配置。
