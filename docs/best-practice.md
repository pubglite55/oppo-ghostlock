# 开发最佳实践

## 代码规范

### 目录结构

```
exploit/
├── src/           # 源代码
│   ├── *.c        # C 源文件
│   ├── *.h        # 头文件
│   └── *.S        # 汇编文件
├── targets/       # 设备特定配置
│   └── <device>/target.h
└── test-programs/ # 测试程序
```

### 命名规范

- **函数名**: 小写下划线 (`slide_leak_kernel_base`, `prepare_kernel_page`)
- **宏定义**: 大写下划线 (`KIMAGE_TEXT_BASE`, `MM_STRUCT_SZ`)
- **变量名**: 小写下划线 (`page_base`, `fake_lock`, `kaslr_slide`)
- **文件名**: 小写下划线 (`slide.c`, `fops.c`, `pipe.c`)

### 编码约定

- 使用 `pr_info`, `pr_warning`, `pr_error` 宏输出日志
- 使用 `SYSCHK()` 宏检查系统调用返回值
- 使用 `atomic_int` 实现线程间同步
- 错误处理: 检查返回值，输出错误信息，适当清理资源

## 核心实现原理

### GhostLock 触发机制

```c
// 3 个 futex words
uint32_t f_wait;       // waiter 等待的 futex
uint32_t f_pi_target;  // PI 锁目标
uint32_t f_pi_chain;   // PI 锁链

// 触发流程:
// 1. waiter: FUTEX_LOCK_PI(f_pi_chain) → 锁定链
// 2. waiter: FUTEX_WAIT_REQUEUE_PI(f_wait → f_pi_target) → 等待 requeue
// 3. owner:  FUTEX_LOCK_PI(f_pi_target) → 锁定目标
// 4. owner:  FUTEX_LOCK_PI(f_pi_chain) → 阻塞 (被 waiter 锁定)
// 5. main:   FUTEX_CMP_REQUEUE_PI(f_wait → f_pi_target) → 触发竞争
```

### 类型混淆机制

```
ashmem_area.name[88] ↔ configfs_buffer.bin_buffer

写入 ashmem name:
  ASHMEM_SET_NAME(fd, "AAAA...") → 写入 ashmem_area + 0
  name[88] 位置的值成为 configfs_buffer.bin_buffer 指针

读取 ashmem (configfs read_iter):
  内核读取 bin_buffer + offset → copy_to_user
  控制 bin_buffer = 任意内核地址 → 任意内核读
```

### 帧大小验证方法

```bash
# 从 IDA output.objdump 验证
aarch64-linux-gnu-objdump -d vmlinux | grep -A 5 "<__arm64_sys_futex>"

# 关键指令: SUB SP, SP, #imm
# 帧大小 = imm 值
```

## 优化记录

### GhostLock 时序优化

**问题**: FUTEX_CMP_REQUEUE_PI 返回 errno=35 (EAGAIN)

**原因**: waiter 调用 FUTEX_WAIT_REQUEUE_PI 后，内核需要时间将其加入 futex hash table。如果主线程在 waiter 真正阻塞前调用 requeue，会失败。

**解决方案**: waiter 调用 FUTEX_WAIT_REQUEUE_PI 后等待 3 秒。

**效果**: requeue ret=1，GhostLock 触发成功。

### ashmem 路径优化

**问题**: `/dev/ashmem` 返回 EACCES (errno=13)

**原因**: SELinux 限制 shell 域访问 `ashmem_device` 类型

**解决方案**: 使用 UUID 后缀路径 `/dev/ashmem874642ac-55fc-4f92-8d57-c514c4666592`

**效果**: ashmem 可正常打开。

## 安全规范

> [!WARNING]
> 本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。

- **权限控制**: exploit 需要 shell 权限 (uid=2000)
- **SELinux**: 设备 SELinux 为 Enforcing，限制部分操作
- **kptr_restrict**: 值为 2，/proc/kallsyms 返回全零
- **KPTI**: 启用 (CONFIG_UNMAP_KERNEL_AT_EL0=y)，阻止时序侧信道
