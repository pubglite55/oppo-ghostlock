# 技术知识沉淀

## Kernel 5.10 futex_wake 行为

**关键发现 (Dere3046 #9)**: futex_wake 在 5.10/5.15/6.1/6.12 完全相同

```c
// core.c — 所有版本完全相同
plist_for_each_entry_safe(this, next, &hb->chain, list) {
    if (match_futex(&this->key, &key)) {
        if (++ret >= nr_wake)
            break;
    }
}
```

- `nr_wake=0` 没有特殊优化 — `hb_waiters_pending()` 返回 true 时一定遍历整条 hash chain
- 唯一跳过遍历的条件是 bucket 完全空
- 之前观察到的 1.0-1.7x timing ratio 是**用户态代码 bug**，不是内核实现差异

## IDA 验证的帧大小

| 函数 | 仓库旧值 | IDA 实际值 | 来源 |
|------|---------|-----------|------|
| `__arm64_sys_futex` | 0x70 | **0x90** | `SUB SP,SP,#0x90` |
| `do_futex` | 0x130 | **0x70** | `SUB SP,SP,#0x70` |
| `futex_wait_requeue_pi` | 0x1A0 | 0x1A0 | ✓ |
| `__arm64_sys_pselect6` | 0x90 | **0xA0** | `SUB SP,SP,#0xA0` |
| `core_sys_select` | 0x1D0 | **0x1C0** | `SUB SP,SP,#0x1C0` |
| `do_select` | 0x390 | **0x3C0** | `STP+0x60` + `SUB+0x360` |
| `binder_ioctl` | 0xF0 | **0xD0** | `SUB SP,SP,#0xD0` |

## rt_mutex_waiter 结构布局

```c
// kernel 5.10 (CONFIG_DEBUG_RT_MUTEXES not set)
struct rt_mutex_waiter {
    struct rb_node tree_entry;      // +0x00 (24 bytes)
    struct rb_node pi_tree_entry;   // +0x18 (24 bytes)
    struct task_struct *task;       // +0x30 (8 bytes)
    struct rt_mutex_base *lock;     // +0x38 (8 bytes)
    unsigned int prio;              // +0x40 (4 bytes)
    u64 deadline;                   // +0x48 (4 bytes)
};  // size = 0x50 (80 bytes)
```

## SLUB 分配器参数

| 参数 | 值 | 来源 |
|------|-----|------|
| MM_STRUCT_SZ | 0x3c0 (960B) | pahole 验证 |
| MM_ORDER | 3 | SLUB order 计算: 32KB slabs |
| futex_hashsize | 2048 | 8 CPUs * 256 |
| CONFIG_NR_CPUS | 32 | 编译时最大值 |
| nr_cpu_ids | 8 | 运行时 CPU 数 |

## core_sys_select 栈布局 (IDA 验证)

```c
// NFDS=320 → v17=40 < 0x2B(43) → 使用栈缓冲区
v17 = ((320+63)/8) & mask = 40;
if (v17 < 0x2B) {
    v18 = v35;  // 栈缓冲区, SP+0x50
} else {
    v18 = kvmalloc_node(6 * v17, ...);  // 堆
}
```

- v35[32] 在 core_sys_select SP+0x50 到 SP+0x10F (256B)
- 6 个 fd_set 各 40B
- 用户数据在前 120B, 结果在后 120B

## pselect 帧链布局

```
stack_top
  │
  │ pselect6 frame (0xA0 bytes)
  │   SP_pselect6 = stack_top - 0xA0
  │
  │ core_sys_select frame (0x1C0 bytes)
  │   SP_core = stack_top - 0x260
  │   fd_set data at SP_core + 0x50 = stack_top - 0x210
  │
  │ do_select frame (0x3C0 bytes)
  │   SP_do = stack_top - 0x620
  │   waiter at stack_top - 0x288
  │
stack_bottom
```

## Ashmem strcpy 行为

OPPO 内核 (5.10.236) 的 ashmem SET_NAME 和 GET_NAME 均使用 **strcpy 行为**：遇第一个 NUL 字节停止拷贝。

**关键洞察**: 问题不是 "NUL 字节存在"，而是 NUL 字节出现在 write offset 的起始位置。configfs blob 的 page 地址在 offset 5，内核地址（如 0xffffffc0...）little-endian 下第一个字节为 0x00 → strcpy 在 offset 5 处不拷贝任何内容。

**导致 configfs type confusion 不可用**。

## 设备 kernel 日志不可访问

OPPO Find N2 (serial=84cb96e2) 无法获取 kernel panic 日志:
- `adb shell dmesg` → `klogctl: Permission denied` (SELinux deny syslog_read)
- `/sys/fs/pstore/` → 空目录, 无 ramdump 文件
- logcat 无 kernel panic 相关日志
