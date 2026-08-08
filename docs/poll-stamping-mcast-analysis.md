# Poll Stamping via MCAST_JOIN_SOURCE_GROUP — 完整分析报告

**设备**: OPPO Find N2 (PGU110), kernel 5.10.236-android12-9-o-g74d132f4467a  
**漏洞**: CVE-2026-43499 (GhostLock rtmutex stack UAF)  
**日期**: 2026-08-02  
**状态**: ❌ MCAST_JOIN_SOURCE_GROUP 双重阻塞：① 4字节覆盖缺口 (264 vs 268) ② lock 字段残留为 NULL (rt_mutex_init_waiter 清零)  
**参考**: [看雪 #291972 一加ACE5 GhostLock适配](https://bbs.kanxue.com/thread-291972.htm)、[brszzz 博客](https://brszzz.github.io/2026/07/12/CVE-2026-43499-GhostLock-6.6-adaptation/)

---

## 1. Poll Stamping 技术概述

### 1.1 核心原理

GhostLock (CVE-2026-43499) 是 Linux 内核 futex PI requeue 路径中的栈 UAF：

1. `FUTEX_WAIT_REQUEUE_PI` 在内核栈上分配 `rt_mutex_waiter` 结构
2. `task_blocks_on_rt_mutex` 设置 `task→pi_blocked_on = &waiter`（指向栈上的 waiter）
3. 超时/竞态导致 waiter 被释放，但 `pi_blocked_on` 可能残留指向已释放的栈内存
4. 同线程调用 syscall → 内核栈拷贝覆盖残留位置
5. `sched_setattr` 触发 `rt_mutex_adjust_pi` → 沿残留指针走伪造的 waiter → rb_erase 任意写

### 1.2 为什么选择 MCAST_JOIN_SOURCE_GROUP

`setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, buffer, len)` 的调用链：

```
__arm64_sys_setsockopt  (0x10)
__sys_setsockopt        (0x80)
do_ipv6_setsockopt      (0x2D0)  ← do_ipv6_mcast_group_source 被内联
```

`do_ipv6_setsockopt` 中 `struct group_source_req greqs` 分配在栈上，`copy_from_user` 将用户 buffer 拷贝到栈。与其他 syscall 相比：

| Syscall | 栈帧总大小 | 用户数据位置 | 可达 waiter? |
|---------|-----------|------------|-------------|
| pselect | 0x620 | fd_set 在 SP-0x210 | ❌ 120B 间隙（do_select 未内联） |
| sendmsg | 0x2F0 | msghdr 在 SP-0x270 | ❌ 帧太浅 |
| sendmmsg | 0x430 | mmsghdr 在 SP-0x240 | ❌ 112B 间隙 |
| poll | 0x4B0 | pollfd 在堆上 | ❌ 堆分配 |
| **MCAST_JOIN_SOURCE_GROUP** | **0x360** | **greqs 在 SP+0x48** | **✅ 接近 waiter 位置** |

MCAST_JOIN_SOURCE_GROUP 是 5.10 内核中唯一能将用户数据拷贝到 waiter 附近的 syscall。

---

## 2. IDA 验证的栈帧布局

### 2.1 WRPI 路径（futex_wait_requeue_pi）

```
futex_wait_requeue_pi 帧大小: 0x1A0 (SUB SP, SP, #0x1A0)

SP+0x000  ┌─────────────────────────┐
          │  局部变量 (0x140)        │
          │  v141[3] @0x90 = rt_waiter.tree_entry (24B)
          │  v142[3] @0xA8 = rt_waiter.pi_tree_entry (24B)
          │  v143    @0xC0 = rt_waiter.task (8B)
          │  v144    @0xC8 = rt_waiter.lock (8B)
          │  v145    @0xD0 = rt_waiter.prio (8B)
          │  v146    @0xD8 = rt_waiter.deadline (8B)
SP+0x140  ├─────────────────────────┤
          │  保存 x29,x30,x19-x28   │  (0x60)
SP+0x1A0  └─────────────────────────┘
```

**完整调用链帧大小**:
```
__arm64_sys_futex:   0x90
do_futex:            0x70
futex_wait_requeue_pi: 0x1A0
合计: 0x2A0

rt_waiter 在帧内 offset 0x90 → 绝对位置 SP_base - 0x210
```

### 2.2 setsockopt 路径（do_ipv6_setsockopt）

```
do_ipv6_setsockopt 帧大小: 0x2D0 (STP X29,X30,[SP,#-0x60+var_s0]! → SP -= 0x210)

SP+0x000  ┌─────────────────────────┐
          │  v151    @0x00 = 临时变量
          │  v153    @0x08 = rtnl 标志
          │  v154    @0x10 = sk 指针
          │  v155[3] @0x18 = 临时数组
          │  v156    @0x30 = 临时
          │  v157    @0x38 = 临时
          │  v158    @0x44 = optval 首4字节
SP+0x048  │  v159[17]@0x48 = greqs buffer (264B)  ← copy_from_user 目标
SP+0x150  │  v160[33]@0x158 = compat buffer (260B)
SP+0x260  │  v_10    @0x260 = 临时
SP+0x270  ├─────────────────────────┤
          │  保存 x29,x30,x19-x28   │  (0x60)
SP+0x2D0  └─────────────────────────┘
```

**完整调用链帧大小**:
```
__arm64_sys_setsockopt: 0x10
__sys_setsockopt:       0x80
do_ipv6_setsockopt:     0x2D0
合计: 0x360

greqs (v159) 在帧内 offset 0x48 → 绝对位置 SP_base - 0x318
```

### 2.3 Offset 计算

```
waiter 绝对位置:  SP_base - 0x210
greqs 绝对位置:   SP_base - 0x318
Delta = 0x318 - 0x210 = 0x108 (264 字节)

user buffer 中 waiter 数据应放在 offset 0x108
```

---

## 3. 测试过程

### 3.1 第一轮：原始代码（offset 0x34）

原始 `main.c` 使用 offset 0x34（来自 IonStackQuest3 的32-bit 路径）：

```
CMP_REQUEUE_PI returned errno=35    ← EDEADLK，requeue 失败
WRPI returned errno=110             ← 超时
ASHMEM_MISC_FOPS not replaced!      ← rb_set_parent 未执行
```

**问题 1**: errno=35 (EDEADLK) — owner 在 requeue 前阻塞在 `f_pi_chain`，内核死锁检测拒绝 requeue。

### 3.2 第二轮：修复 errno=35

**根因**: owner 线程在 `FUTEX_CMP_REQUEUE_PI` 之前就调用 `FUTEX_LOCK_PI(f_pi_chain)` 阻塞。内核 `rt_mutex_start_proxy_lock` 做 FULL_CHAINWALK 死锁检测，发现 owner→f_pi_chain→waiter→f_pi_target→owner 循环，返回 -EDEADLK。

**修复**: owner 等待 `requeue_done` 信号后再阻塞在 `f_pi_chain`。

```
CMP_REQUEUE_PI returned errno=0     ← requeue 成功！
WRPI returned errno=110             ← 超时（waiter 在 PI 树中排队）
ASHMEM_MISC_FOPS not replaced!      ← 仍然失败
```

### 3.3 第三轮：引入 UNLOCK_PI 竞态

requeue 成功后，waiter 在 PI 树中排队。owner 调用 `FUTEX_UNLOCK_PI(f_pi_target)` 释放锁唤醒 waiter：

```
CMP_REQUEUE_PI returned errno=0
WRPI returned errno=0               ← waiter 被 UNLOCK_PI 唤醒，拿到锁
UNLOCK_PI returned 0
ASHMEM_MISC_FOPS not replaced!
```

**关键发现**: `FUTEX_UNLOCK_PI` 检查 owner TID（line 2984: `if ((uval & FUTEX_TID_MASK) != vpid) return -EPERM`）。只有 owner 线程能解锁。独立的 race 线程调用 UNLOCK_PI 会返回 -EPERM。

### 3.4 第四轮：owner 持有锁，waiter 超时

owner 始终持有 `f_pi_target`，requeue 将 waiter 排入 PI 树，5 秒超时后 `remove_waiter` 清除 `pi_blocked_on`：

```
CMP_REQUEUE_PI returned errno=0
WRPI returned errno=110             ← 5 秒超时
ASHMEM_MISC_FOPS not replaced!
```

### 3.5 第五轮：offset 0x108 + 264 字节 buffer

使用 IDA 计算的精确 offset 0x108：

```
CMP_REQUEUE_PI returned errno=0
WRPI returned errno=0               ← UNLOCK_PI 唤醒
spray 5000 iterations complete
sched_setattr returned 0
ASHMEM_MISC_FOPS not replaced!
```

---

## 4. 失败根因分析

### 4.1 4 字节覆盖缺口（硬阻塞）

MCAST_JOIN_SOURCE_GROUP 的 `copy_from_user` 大小硬编码为 264 字节（`MOV W2, #0x108`）：

```
waiter 结构布局 (80 字节):
  +0x00: tree_entry.parent_color   (8B)  ← buffer[0x108] ✅ 可控
  +0x08: tree_entry.rb_right       (8B)  ← buffer[0x110] ✅ 可控
  +0x10: tree_entry.rb_left        (8B)  ← buffer[0x118] ✅ 可控
  +0x18: pi_tree_entry.parent_color(8B)  ← buffer[0x120] ✅ 可控
  +0x20: pi_tree_entry.rb_right    (8B)  ← buffer[0x128] ✅ 可控
  +0x28: pi_tree_entry.rb_left     (8B)  ← buffer[0x130] ✅ 可控
  +0x30: task                      (8B)  ← buffer[0x138] ✅ 可控（前4B）
  +0x38: lock                      (8B)  ← buffer[0x140] ❌ 超出264字节！
           ↑ rt_mutex_adjust_pi 读取此字段
```

**264 字节拷贝覆盖 waiter[0x00..0x37]，但 lock 字段在 waiter[0x38] = buffer[0x140] = offset 268，刚好超出 4 字节。**

#### struct group_source_req 对齐验证

```c
// include/uapi/linux/socket.h
struct __kernel_sockaddr_storage {
    union {
        struct {
            __kernel_sa_family_t ss_family;  // 2 bytes
            char __data[_K_SS_MAXSIZE - sizeof(unsigned short)];  // 126 bytes
        };
        void *__align;  // 8-byte alignment
    };
};  // total: 128 bytes (8-byte aligned)

// include/uapi/linux/in.h
struct group_source_req {
    __u32 gsr_interface;                        // 4 bytes @ offset 0
    // 4 bytes padding (to align gsr_group to 8)
    struct __kernel_sockaddr_storage gsr_group;  // 128 bytes @ offset 8
    struct __kernel_sockaddr_storage gsr_source; // 128 bytes @ offset 136
};  // total: 264 bytes (with padding)
```

`sizeof(struct group_source_req)` = 264 字节（4 + 4 padding + 128 + 128）。编译器生成 `MOV W2, #0x108` (264)。

源码 `copy_from_sockptr(greqs, optval, sizeof(*greqs))` 使用 `sizeof(*greqs)` = 264，不是 optlen。即使传 optlen=280，内核仍只拷贝 264 字节。

### 4.2 lock 字段残留为 NULL（双重阻塞）

即使 lock 字段在 memset 范围外（memset 清零 264 字节从 offset 0x48 到 0x14F），lock 字段在 offset 0x10C（绝对位置 SP_base - 0x1D8），在 memset 范围之外。

但 lock 字段的残留值来自 WRPI 帧的局部变量。WRPI 帧中对应位置（offset 0x78）是 `var_C8`，`rt_mutex_init_waiter` 将 waiter→lock 初始化为 NULL。

**关键代码** (`include/linux/rtmutex_common.h`):
```c
static inline void rt_mutex_init_waiter(struct rt_mutex_waiter *waiter) {
    memset(waiter, 0, sizeof(*waiter));
    // ... debug_init_list
}
```

`memset(waiter, 0, sizeof(*waiter))` 将整个 80 字节的 waiter 清零，包括 lock 字段。

**即使 UNLOCK_PI 竞态成功唤醒 waiter，waiter→lock 仍然是 NULL**（waiter 获取锁后 lock 字段不会被更新）。

**结果: lock = NULL → `rt_mutex_adjust_pi` 检查 `!waiter→lock` 直接返回，rb_erase 不触发。这是 MCAST_JOIN_SOURCE_GROUP 的双重阻塞。**

### 4.3 do_ipv6_setsockopt 中所有选项的最大拷贝

通过 IDA 反编译确认 `do_ipv6_setsockopt` 中所有 `copy_from_user` 调用的大小：

| 地址 | 拷贝大小 | 对应选项 |
|------|---------|---------|
| 0x95c2148 | 0x108 (264) | MCAST_JOIN_SOURCE_GROUP (compat 路径 memset) |
| 0x95c216c | 0x108 (264) | MCAST_JOIN_SOURCE_GROUP (64-bit copy_from_user) |
| 0x95c21d4 | 0x104 (260) | MCAST_JOIN_SOURCE_GROUP (compat copy_from_user) |
| 0x95c2210 | 0x14 (20) | MCAST_JOIN_GROUP / MCAST_LEAVE_GROUP |
| 0x95c2248 | 0x14 (20) | MCAST_BLOCK_SOURCE / MCAST_UNBLOCK_SOURCE |
| 0x95c2320 | 0x88 (136) | compat group_source_req |
| 0x95c2588 | 0x14 (20) | IPV6_JOIN_GROUP / IPV6_LEAVE_GROUP |

**最大拷贝为 264 字节。没有选项能拷贝 272+ 字节。**

### 4.4 optlen 参数不影响拷贝大小

反编译确认，64-bit 路径的 `copy_from_user` 大小硬编码为 `MOV W2, #0x108`（264），不使用 `optlen` 参数：

```c
// IDA 反编译的 64-bit 路径
else if ( v8 >= 0x108 )  // optlen >= 264
{
    copy_from_user_71961(v159, a3, 264);  // 固定 264 字节，不使用 v8 (optlen)
}
```

即使传 optlen=280，内核仍只拷贝 264 字节。

### 4.5 pi_blocked_on 生命周期

```
task_blocks_on_rt_mutex:    task→pi_blocked_on = waiter  ← 设置
remove_waiter:              current→pi_blocked_on = NULL  ← 清除
rt_mutex_wait_proxy_lock → __rt_mutex_slowlock → hrtimer callback → remove_waiter
```

**两种路径都会清除 pi_blocked_on**:

1. **超时路径**: hrtimer callback → `remove_waiter()` → `pi_blocked_on = NULL` → WRPI 返回
2. **UNLOCK_PI 路径**: `wake_futex_pi` → `mark_wakeup_next_waiter` 不清除 `pi_blocked_on`，但 waiter 通过 `rt_mutex_wait_proxy_lock` → `try_to_take_rt_mutex` 获取锁 → 从 rb-tree 移除

**UNLOCK_PI 路径的竞态窗口**:
- UNLOCK_PI 释放锁 → 唤醒 waiter
- waiter 在 `rt_mutex_wait_proxy_lock` 中 `try_to_take_rt_mutex` 成功
- `pi_blocked_on` 仍指向栈 waiter（未被清除）
- 但 waiter 已从 rb-tree 移除 → `task→pi_waiters` 为空 → chain walk 无操作

---

## 5. FUTEX_UNLOCK_PI 所有权限制

```c
// kernel/futex/core.c:2984
if ((uval & FUTEX_TID_MASK) != vpid)
    return -EPERM;
```

`FUTEX_UNLOCK_PI` 检查调用线程是否是锁的 owner。只有 owner 线程能成功调用。独立的 race 线程调用会返回 -EPERM。

这意味着无法用独立线程做 UNLOCK_PI 竞态，必须由 owner 线程自己调用。

---

## 6. kanxue 帖子关键评论

来自 [看雪帖子 #291972](https://bbs.kanxue.com/thread-291972.htm) 评论区：

> **daiviswang (6楼)**: "piexl10 成功是因为 pselect 前面的 do_select inline 的 没有额外的栈帧"

> **daiviswang (7楼)**: "这个应该是堆栈窗口偏移了。pselect 的 fd_set 没有完美覆盖掉栈上的 waiter"

这解释了为什么 pselect 路径在 Pixel 10 上可行（`do_select` 内联，无额外栈帧），但在 OPPO 5.10 上不可行（`do_select` 未内联，120B 间隙）。

---

## 7. 与 OnePlus 13T (6.6.89) 的对比

| 项目 | OPPO Find N2 (5.10.236) | OnePlus 13T (6.6.89) |
|------|------------------------|---------------------|
| rt_mutex_waiter 大小 | 80B (0x50) | 112B (0x70) |
| waiter→lock offset | +0x38 | +0x58 |
| MCAST 拷贝大小 | 264B | 264B |
| lock 字段覆盖? | ❌ 差4字节 | ❌ 差更多 |
| 主要栈控制方法 | MCAST_JOIN_SOURCE_GROUP | pselect6 |
| pselect 可行? | ❌ do_select 未内联 | ✅ do_select 内联 |
| CONFIG_UBSAN_TRAP | 未知 | ✅ (导致 PI chain walk 崩溃) |

---

## 8. 可能的推进方向

### 8.1 寻找能拷贝 272+ 字节的 syscall

需要在内核中搜索 `copy_from_user` 调用，目标大小 ≥ 272 字节，且目标在栈上。候选：
- `sendmsg` + `SCM_RIGHTS`（发送文件描述符）
- `recvmmsg`（接收多条消息）
- `process_vm_readv/writev`（iovec 数组）
- `clone3`（clone_args 结构）
- 其他协议的 setsockopt handler

### 8.2 两次 syscall 栈布局

用 MCAST_JOIN_SOURCE_GROUP 覆盖 waiter[0x00..0x37]，再用另一个 syscall 覆盖 waiter[0x38]（lock 字段）。关键：第二个 syscall 的栈帧必须将其拷贝目标对齐到 waiter lock 字段的绝对位置。

### 8.3 换用 pselect 路径

参考 kanxue 评论，pselect 在 Pixel 10 上成功是因为 `do_select` 被内联。在 OPPO 5.10 上 `do_select` 未内联，产生 120B 间隙。但可以通过调整 NFDS 或使用 `-O2` 编译优化来尝试缩小间隙。

### 8.4 接受 lock=0，换利用思路

如果 lock 字段无法控制，可以考虑：
- 不依赖 `rt_mutex_adjust_pi` 的 rb_erase
- 寻找其他读取 `pi_blocked_on` 并操作 rb-tree 的代码路径
- 使用 `pi_blocked_on` 残留做信息泄漏而非任意写

### 8.5 参考 brszzz 的方法论

[brszzz 的 OnePlus 13T 适配帖](https://brszzz.github.io/2026/07/12/CVE-2026-43499-GhostLock-6.6-adaptation/) 使用的方法：

1. root kallsyms → A 类符号偏移（相对 `_text`，KASLR 抵消）
2. BTF + bpftool → B 类结构体偏移（比内核源码 + pahole 更直接）
3. config.gz + iomem → C 类布局常数
4. IDA 读 flat Image → 解决 kallsyms 缺失的 static 变量
5. 逐子技术对比 BTF → 验证伪造结构体布局兼容性

**brszzz 的关键发现**:
- `file_operations` 字段偏移在不同内核版本间会静默变化（6.6 vs Pixel 差 8 字节）
- `task_struct.pi_lock` 在 6.6 上是 0x90c（Pixel 是 0x924），差 0x18
- `CONFIG_UBSAN_TRAP` 把 UBSAN warn 变成 BRK → 必崩
- OnePlus 13T 上 slide 的 PI chain walk 触发 UBSAN array bounds → BRK #0x5512 → panic

**适配 OPPO Find N2 的教训**:
- 5.10 内核的 `struct group_source_req` 对齐后 264 字节，lock 字段差 4 字节
- `do_select` 未内联导致 pselect 路径有 120B 间隙
- 需要找到能拷贝 272+ 字节到栈上的 syscall，或换用完全不同的利用思路

---

## 9. 结论

MCAST_JOIN_SOURCE_GROUP 在 OPPO Find N2 (kernel 5.10.236) 上存在**双重阻塞**：

1. **4 字节覆盖缺口**: `struct group_source_req` 编译后 264 字节（含对齐 padding），waiter→lock 在 offset 268，copy_from_user 只拷贝 264 字节
2. **lock 字段残留为 NULL**: `rt_mutex_init_waiter` 将 waiter 清零，lock=0，`rt_mutex_adjust_pi` 检查 `!waiter→lock` 直接返回

即使 UNLOCK_PI 竞态成功（pi_blocked_on 残留指向栈 waiter），rb_erase 也不会触发。

**建议**: 改用能拷贝 272+ 字节的 syscall（如 `sendmsg` + `SCM_RIGHTS`），或接受 lock=0 的限制换用不依赖 rb_erase 的利用思路。

[brszzz 的 OnePlus 13T 适配帖](https://brszzz.github.io/2026/07/12/CVE-2026-43499-GhostLock-6.6-adaptation/) 使用的方法：
1. root kallsyms → A 类符号偏移
2. BTF + bpftool → B 类结构体偏移
3. config.gz + iomem → C 类布局常数
4. IDA 读 flat Image → 解决 kallsyms 缺失的 static 变量
5. 逐子技术对比 BTF → 验证伪造结构体布局兼容性

---

## 9. 代码修改记录

### 9.1 errno=35 修复

`owner_thread` 改为等待 `requeue_done` 信号后再阻塞：

```c
// 修复前: owner 立即阻塞 → requeue 检测到死锁 → EDEADLK
futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

// 修复后: owner 等待 requeue 完成后再阻塞
while (!atomic_load(&requeue_done)) usleep(100);
futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
```

### 9.2 Poll Stamping offset 更新

```c
// 修复前: 32-bit 路径 offset
memcpy(buffer + 0x34, rb_payload, 0x50);

// 修复后: IDA 验证的64-bit 路径 offset
memcpy(buffer + 0x108, rb_payload, 0x34);
```

### 9.3 UNLOCK_PI 竞态

```c
// owner 在 requeue 后调用 UNLOCK_PI 唤醒 waiter
while (!atomic_load(&requeue_done)) usleep(10);
long ret = futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
```

---

## 10. 关键文件

| 文件 | 说明 |
|------|------|
| `exploit/src/main.c` | GhostLock 触发 + poll stamping 主逻辑 |
| `exploit/src/common.h` | 公共定义、偏移、函数声明 |
| `exploit/targets/oppo-find_n2/target.h` | OPPO Find N2 内核偏移 |
| `docs/syscall-stack-analysis.md` | syscall 栈帧可达性分析 |
| `docs/rt_mutex-redesign-analysis.md` | rt_mutex 路径分析 |
| `docs/poll-stamping-mcast-analysis.md` | 本文档 |
| 内核源码 `kernel/locking/rtmutex.c` | rt_mutex PI chain walk 实现 |
| 内核源码 `kernel/futex/core.c` | futex_wait_requeue_pi / futex_unlock_pi |
| 内核源码 `net/ipv6/ipv6_sockglue.c` | do_ipv6_setsockopt / MCAST_JOIN_SOURCE_GROUP |

---

*Generated: 2026-08-02*
