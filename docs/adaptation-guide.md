# GhostLock 适配指南

## 核心原则

**简单适配偏移是不可能成功的。** 不同内核的栈布局、结构体偏移、系统调用行为都可能不同。

---

## 两个关键部分

### 1. 栈覆盖 (Stack Overwrite)

**要求**: 覆盖被释放的内核栈，且该栈在用户空间可控。

**Pixel 10 成功原因**: pselect 的 `stack_fds` 正好和 `rt_waiter` 在内核栈上重合。

**OPPO Find N2 失败原因**:

```
waiter 位置: stack_top - 0x358 (856B)
pselect fd_set: stack_top - 0x1f8 (504B)
差距: 352B — fd_set 无法触及 waiter
```

**适配思路**:

1. **分析目标内核的系统调用栈布局**
   ```bash
   # 从 boot.img 提取 vmlinux
   ./extract-vmlinux boot.img > vmlinux

   # 分析关键函数的栈帧
   aarch64-linux-gnu-objdump -d vmlinux | grep -A 50 "<sys_pselect6>"
   ```

2. **找到用户可控数据能到达 waiter 位置的 syscall**
   - pselect: 检查 fd_set 位置
   - process_vm_readv: 检查 iovec 位置
   - binder: 检查 ioctl 数据位置
   - 其他 syscall: io_uring, nfsetsockopt 等

3. **验证栈覆盖**
   - 实现可控 panic，确认覆盖位置
   - 使用 `/proc/sys/kernel/sysrq` 触发 panic
   - 分析 panic 日志中的栈回溯

### 2. 结构体适配

**5 系内核 vs 6 系内核**:

| 结构体 | 5.x 偏移 | 6.x 偏移 | 说明 |
|--------|----------|----------|------|
| rt_mutex_waiter.task | 0x30 | 可能不同 | 需要 pahole 验证 |
| rt_mutex_waiter.lock | 0x38 | 可能不同 | |
| task_struct.cred | 0x780 | 可能不同 | |
| mm_struct 大小 | 0x3c0 | 可能不同 | 影响 SLUB order |

**提取偏移**:

```bash
# 从设备提取 vmlinux
adb pull /proc/version  # 获取内核版本
# 下载对应内核源码或固件包

# 用 pahole 提取偏移
pahole -C rt_mutex_waiter vmlinux
pahole -C task_struct vmlinux
pahole -C mm_struct vmlinux
pahole -C cred vmlinux
```

---

## 适配流程

### 阶段 1: 栈覆盖验证

1. **分析目标内核栈布局**
   - 提取 vmlinux
   - 反汇编关键 syscall 函数
   - 计算栈帧大小和变量位置

2. **实现可控 panic**
   ```c
   // 在 slide.c 中添加 panic 触发
   void trigger可控_panic(void) {
       // 方法 1: sysrq
       int fd = open("/proc/sys/kernel/sysrq", O_WRONLY);
       write(fd, "c", 1);  // 触发 crash

       // 方法 2: 故意访问非法地址
       volatile int *ptr = (volatile int *)0xdeadbeef;
       *ptr = 0;
   }
   ```

3. **验证栈覆盖位置**
   - 分析 panic 日志
   - 确认覆盖的数据在预期位置
   - 调整 syscall 参数直到覆盖正确

### 阶段 2: 结构体适配

1. **提取目标设备偏移**
   - 用 pahole 从 vmlinux 提取
   - 更新 `target.h`

2. **验证 mm_struct 泄漏**
   - 运行 KernelSnitch
   - 确认能泄漏 mm_struct 地址

3. **验证 GhostLock 触发**
   - 测试 FUTEX_CMP_REQUEUE_PI
   - 确认能创建悬空指针

### 阶段 3: 完成提权链

1. **pipe 物理读写**
   - 验证 pipe buffer 覆盖
   - 实现任意内核地址读写

2. **cred 结构体修补**
   - 找到当前进程的 task_struct
   - 修改 uid/gid/capabilities

3. **SELinux 绕过**
   - 修改 cred security 字段
   - 或禁用 SELinux enforcing

---

## 常见问题

### Q: 如何判断栈布局是否兼容?

A: 反汇编目标内核的 syscall 函数，计算栈帧大小和变量偏移。如果 waiter 位置和用户可控数据位置重合，则兼容。

### Q: 如果栈布局不兼容怎么办?

A: 需要找到其他能控制内核栈的 syscall。可能需要：
- 分析更多 syscall 的栈布局
- 组合多个 syscall
- 或者放弃该设备

### Q: 结构体偏移不同怎么办?

A: 必须用 pahole 从目标设备的 vmlinux 提取。不能假设偏移相同。

### Q: 如何测试栈覆盖是否正确?

A: 实现可控 panic，分析 panic 日志中的栈回溯。确认覆盖的数据在预期位置。

---

## 参考资源

- NebuSec CyberMeowfia: https://github.com/NebuSec/CyberMeowfia
- GhostLock CVE-2026-43499: https://nebusec.ai/research/ionstack-part-2/
- Linux 内核源码: https://github.com/torvalds/linux
- pahole 工具: https://github.com/acmel/dwarves
