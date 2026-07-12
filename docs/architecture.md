# 架构设计文档

## 设计理念

本项目基于 [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) 的 exploit 架构，针对 OPPO Find N2 设备进行适配。核心设计原则：

1. **模块化** — exploit 链分为独立阶段，每个阶段可单独测试
2. **设备适配** — 通过 `target.h` 隔离设备特定偏移
3. **防御规避** — 绕过 KPTI、SELinux、kptr_restrict 等安全机制

## 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Exploit Chain (6 stages)                   │
├─────────────────────────────────────────────────────────────┤
│ Stage 1: Firefox CVE-2026-10702                             │
│   SpiderMonkey type confusion → fake TypedArray → AAW       │
├─────────────────────────────────────────────────────────────┤
│ Stage 2: KASLR Bypass (slide)                               │
│   pselect fd_set → fake fops → boot_id leak → kernel base  │
├─────────────────────────────────────────────────────────────┤
│ Stage 3: mm_struct Leak (KernelSnitch)                      │
│   futex hash collision → timing side-channel → mm_struct    │
├─────────────────────────────────────────────────────────────┤
│ Stage 4: GhostLock Trigger                                  │
│   FUTEX_CMP_REQUEUE_PI → dangling pi_blocked_on → fops     │
├─────────────────────────────────────────────────────────────┤
│ Stage 5: Pipe Physical R/W                                  │
│   pipe_buffer manipulation → physical read/write            │
├─────────────────────────────────────────────────────────────┤
│ Stage 6: Root (cred + SELinux)                              │
│   patch cred → disable seccomp → disable SELinux            │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块详解

### 1. KernelSnitch (mm_struct 泄漏)

**功能**: 通过 futex hash table 碰撞泄漏内核 mm_struct 地址

**原理**:
- Linux futex hash table 的 key 包含进程的 `mm_struct` 指针
- 通过制造 futex hash 碰撞，观察包含 `mm_struct` 的内存区域
- 用时序侧信道 (cache timing) 暴力搜索 2GB direct map 范围

**输入**: futex_hashsize=2048, MM_STRUCT_SZ=0x3c0, MM_ORDER=3
**输出**: mm_struct 内核地址
**依赖**: CONFIG_FUTEX_PI=y

**当前状态**: ❌ KPTI 启用导致时序不准确

### 2. GhostLock 触发

**功能**: 通过 FUTEX_CMP_REQUEUE_PI 竞争条件创建 dangling pi_blocked_on 指针

**原理**:
1. Thread A (waiter) 调用 `FUTEX_WAIT_REQUEUE_PI` 并阻塞
2. Thread B (owner) 调用 `FUTEX_LOCK_PI` 锁定目标
3. Main thread 调用 `FUTEX_CMP_REQUEUE_PI` 触发竞争
4. `remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`
5. waiter 的 `pi_blocked_on` 变成悬空指针

**输入**: 3 个 futex words (f_wait, f_pi_target, f_pi_chain)
**输出**: dangling pi_blocked_on 指针
**已验证**: ✅ FUTEX_CMP_REQUEUE_PI ret=1

### 3. Fake Kernel Page 布置

**功能**: 在 SLUB slab 中布置伪造的内核数据结构

**原理**:
- 使用 SKB payload 通过 sendmsg 发送到内核
- SKB 数据落在 order-3 slab (32KB) 中
- 在 slab 中布置 fake_lock, fake_fops, fake_task 等结构
- fake_lock 的 right 指针指向 `ashmem_misc.fops`

**输入**: mm_struct 地址 (用于计算 slab 基址)
**输出**: fake kernel page at known address
**当前状态**: ❌ 需要 mm_struct 地址

### 4. 类型混淆 (C ashmem)

**功能**: 通过 ashmem/configfs 类型混淆实现任意内核读写

**原理**:
1. GhostLock 覆盖 `ashmem_misc.fops` → 指向 `configfs_bin_file_operations`
2. 打开 `/dev/ashmem` → 内核分配 `ashmem_area` 到 `file->private_data`
3. `ASHMEM_SET_NAME` 写入 name[88] → 控制 `configfs_buffer.bin_buffer` 指针
4. 调用 read/write → 内核通过 `bin_buffer` 执行任意读写

**关键结构重叠**:
```
ashmem_area + 0x88 (name[88])  ↔  configfs_buffer + 0x58 (bin_buffer)
```

**当前状态**: ✅ 理论可行 (C ashmem 已验证)

### 5. Pipe 物理读写

**功能**: 通过 pipe_buffer 实现物理内存读写

**原理**:
- 修改 pipe_buffer 的 page 指针指向 direct map
- 通过 pipe read/write 操作物理内存

**输入**: 任意内核读写 (来自类型混淆)
**输出**: 物理内存读写能力
**当前状态**: ⏳ 依赖类型混淆

### 6. Root 提权

**功能**: 修改 cred 结构体和 SELinux 状态实现 root

**原理**:
- 遍历 `init_task.tasks` 找到当前进程
- 修改 `cred.uid=0`, `cred.capabilities=FULL`, `cred.security.SID=1`
- 清除 seccomp, 禁用 SELinux enforcing

**输入**: 任意内核读写
**输出**: root 权限
**当前状态**: ⏳ 依赖 pipe 物理读写

## 核心业务流程

```
1. Firefox exploit → preload.so (LD_PRELOAD)
   ↓
2. KernelSnitch → 泄漏 mm_struct 地址
   ↓
3. prepare_kernel_page() → 布置 fake kernel page
   ↓
4. FUTEX_CMP_REQUEUE_PI → 触发 GhostLock
   ↓
5. pselect → 操纵内核栈 → 覆盖 ashmem_misc.fops
   ↓
6. 打开 /dev/ashmem → 类型混淆 → 任意读写
   ↓
7. pipe physrw → 物理内存读写
   ↓
8. patch cred → root
```

## 技术选型说明

| 技术 | 选型原因 | 替代方案 |
|------|---------|---------|
| GhostLock (CVE-2026-43499) | 影响范围广 (Linux 2.6.39-7.1)，Android 设备普遍受影响 | 无 |
| FUTEX_CMP_REQUEUE_PI | GhostLock 的触发入口，无需特殊权限 | 无 |
| C ashmem | name[88] 与 configfs_buffer.bin_buffer 重叠，可实现类型混淆 | Rust ashmem 不可用 |
| configfs_bin_file_operations | read_iter/write_iter 使用 bin_buffer 指针，可实现任意读写 | 其他 fops (需验证) |
| pselect stack reclaim | 利用内核栈重用写入 waiter 位置 | sendmsg cmsg (待验证) |

## 关键数据结构

### rt_mutex_waiter (pahole 验证)

```c
struct rt_mutex_waiter {
    +0x00: rb_node tree_entry;      // 24 bytes
    +0x18: rb_node pi_tree_entry;   // 24 bytes
    +0x30: struct task_struct *task; // 8 bytes
    +0x38: struct rt_mutex_base *lock; // 8 bytes
    +0x40: int prio;                // 4 bytes
    +0x48: u64 deadline;            // 8 bytes
};  // 总计 80 bytes
```

### ashmem_area (IDA 验证)

```c
struct ashmem_area {               // 312 bytes (C ashmem)
    +0x00: char name[256];         // ASHMEM_SET_NAME 写入
    +0x88: name[88]                // 与 configfs_buffer.bin_buffer 重叠!
    +0x110: struct list_head unpinned;
    +0x130: size_t size;
};
```

### configfs_buffer (IDA 验证)

```c
struct configfs_buffer {           // 128 bytes
    +0x20: struct mutex mutex;
    +0x50: bool needs_fill;
    +0x58: void *bin_buffer;       // 与 ashmem_area.name[88] 重叠!
    +0x60: unsigned int bin_buffer_size;
    +0x68: unsigned int cb_max_size;
    +0x70: struct configfs_dirent *sd;
    +0x78: struct module *module;
    +0x88: struct configfs_bin_operations *cb;
};
```
