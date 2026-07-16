# GhostLock OPPO Find N2 — 所有测试方法汇总

**设备**: OPPO Find N2 (SM8475/CPH2413), kernel 5.10.236, Android 16  
**漏洞**: CVE-2026-43499 (GhostLock rtmutex stack UAF)  
**日期**: 2026-07-14  

---

## 一、已完成的阶段 ✅

| 阶段 | 状态 | 说明 |
|------|------|------|
| Firefox CVE-2026-10702 | ✅ | SpiderMonkey type confusion → AAW |
| KASLR bypass (slide) | ✅ | pselect side-channel leak nfulnl_logger |
| GhostLock FUTEX 触发 | ✅ | FUTEX_CMP_REQUEUE_PI ret=0 |
| KernelSnitch mm_struct 泄漏 | ✅ | futex hash timing, bruteforce 找到 mm_struct |
| sk_buff reclaim | ✅ | 4/4 send 成功 |
| PR #13 bypass slide | ✅ | 直接计算 kaslr_base |

---

## 二、KASLR 绕过方法（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 1 | pselect side-channel (boot_id leak) | ❌ | fd_set 在堆上，不在栈上 |
| 2 | Prefetch side-channel | ❌ | KPTI 启用 (CONFIG_UNMAP_KERNEL_AT_EL0=y) |
| 3 | /proc/kallsyms | ❌ | Permission denied |
| 4 | /proc/sys/kernel/kptr_restrict | ❌ | Permission denied |
| 5 | /proc/self/maps | ❌ | 只有用户态地址 |
| 6 | /proc/self/stack/wchan/syscall | ❌ | 空或无有用数据 |
| 7 | /proc/self/auxv | ❌ | 只有用户态地址 |
| 8 | /sys/kernel/debug/ | ❌ | Permission denied |
| 9 | keyctl KEYCTL_INSTANTIATE_IOV | ❌ | EOPNOTSUPP (errno=95) |
| 10 | perf_event_open | ❌ | SELinux deny |
| 11 | PR_SET_MM_MAP | ❌ | EPERM (Android blocks) |

---

## 三、CFI 绕过 / Waiter 操纵方法（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 12 | pselect fd_set 栈覆盖 (NFDS=320) | ❌ | waiter 在 fd_set 下方 120B |
| 13 | pselect fd_set 栈覆盖 (NFDS=321) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 14 | pselect fd_set 栈覆盖 (NFDS=344) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 15 | pselect fd_set 栈覆盖 (NFDS=640) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 16 | pselect fd_set 栈覆盖 (NFDS=1024) | ❌ | fd_set 在堆上 (bitmap_alloc) |
| 17 | pselect 栈帧重叠 | ❌ | futex_wait_requeue_pi 和 pselect 是独立调用链 |
| 18 | sendmsg 栈覆盖 | ❌ | 距 waiter 80B，不够近 |
| 19 | sendmmsg 栈覆盖 | ❌ | 距 waiter 112B，不够近 |
| 20 | binder ioctl 栈覆盖 | ❌ | EACCES (shell user 无法访问 /dev/binder) |
| 21 | poll 栈覆盖 | ❌ | pollfd 在堆上 |
| 22 | epoll_wait 栈覆盖 | ❌ | 帧太浅 (0xE0) |
| 23 | setsockopt 栈覆盖 | ❌ | 无栈上复制 |
| 24 | 堆喷射 (5轮测试) | ❌ | pselect 路径导致内核 panic |

---

## 四、内核 R/W 原语（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 25 | configfs R/W (ashmem SET_NAME) | ❌ | ashmem 无 configfs 支持，pread 返回 EOF |
| 26 | pipe physrw | ❌ | 依赖 configfs kernel_read/write_data |
| 27 | /proc/self/mem | ❌ | kptr_restrict 限制 |
| 28 | /dev/mem | ❌ | 不存在 |
| 29 | /dev/ion | ❌ | 只能分配新内存 |
| 30 | dma_heap | ❌ | 只能分配新内存 |

---

## 五、内核信息泄漏（部分成功）

| # | 方法 | 状态 | 结果 |
|---|------|------|------|
| 31 | KernelSnitch mm_struct leak | ✅ | mm_struct=0xffffff89807912c0 |
| 32 | PR_SET_MM_MAP auxv | ❌ | EPERM |
| 33 | /proc/config.gz | ✅ | 可读取内核配置 |

---

## 六、GhostLock 触发（成功但无法利用）

| # | 方法 | 状态 | 结果 |
|---|------|------|------|
| 34 | FUTEX_CMP_REQUEUE_PI | ✅ | ret=0，触发成功 |
| 35 | FUTEX_LOCK_PI (PI 触发) | ✅ | ret=0，触发成功 |
| 36 | sched_setattr_tid (consumer) | ✅ | PI chain walk 触发 |
| 37 | setpriority (consumer) | ✅ | PI chain walk 触发 |

---

## 七、根因总结

### 核心阻塞：没有可用的内核写原语

1. **pselect 在此内核上无法操纵 waiter 结构**（架构性原因）
   - NFDS > 336：fd_set 通过 bitmap_alloc() 分配在堆上
   - NFDS ≤ 336：futex_wait_requeue_pi 和 pselect 是独立调用链，栈帧不重叠
   - 120 字节偏移差无法通过任何 NFDS 值克服

2. **configfs/ashmem 在此内核上不支持**
   - ashmem SET_NAME 使用 strcpy 行为
   - 内核地址 LE 首字节为 NUL → 截断
   - pread 返回 EOF (errno=0)

3. **所有其他内核写入路径都被阻塞**
   - /proc/self/mem: kptr_restrict
   - /dev/mem, /dev/ion: 不存在或无任意访问
   - binder: EACCES (shell user)

### 结论

**这是一个内核安全配置问题，不是代码问题。** OPPO 5.10.236 内核的安全加固阻止了所有已知的 GhostLock 利用路径。

---

## 八、设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)
- **ashmem**: 无 configfs 支持

---

*Generated: 2026-07-14*
