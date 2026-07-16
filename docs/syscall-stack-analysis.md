# Syscall Stack Reachability Analysis for GhostLock Waiter Position

**Date**: 2026-07-14
**Goal**: Find a syscall that writes user-controlled data to the `rt_mutex_waiter` position on the kernel stack (stack_top - 0x270)
**Status**: ❌ No viable stack spray candidate found — sendmmsg gap is 112 bytes (not 8)

---

## Waiter Position Summary (IDA VERIFIED 2026-07-14)

```
waiter struct (rt_mutex_waiter, 80 bytes):
  tree_entry:      stack_top - 0x270  (+0x00)  ← waiter 起始位置
  pi_tree_entry:   stack_top - 0x258  (+0x18)
  task:            stack_top - 0x240  (+0x30)  ← critical
  lock:            stack_top - 0x238  (+0x38)  ← critical
  prio:            stack_top - 0x230  (+0x40)
  deadline:        stack_top - 0x228  (+0x48)

注意: 之前 AGENTS.md 记录 waiter 在 stack_top - 0x288，经 IDA 重新验证为 0x270
```

Target: write user-controlled data to at least `lock` (+0x38) through `deadline` (+0x48).

---

## Syscalls Analyzed

### 1. pselect (BLOCKED — original approach)

| Function | Frame | SP offset |
|----------|-------|-----------|
| `__arm64_sys_pselect6` | 0xA0 | stack_top - 0xA0 |
| `core_sys_select` | 0x1C0 | stack_top - 0x260 |
| `do_select` | 0x3C0 | stack_top - 0x620 |
| **Total** | **0x620** | |

**fd_set data**: `core_sys_select SP + 0x50 = stack_top - 0x210`
**Waiter**: `stack_top - 0x270` (IDA VERIFIED)
**Gap**: 0x60 (96 bytes) — fd_set is ABOVE waiter, cannot reach downward.

**NFDS sweep results**: All NFDS values (320/321/344/640) fail.
- NFDS ≤ 320: fd_set on栈, but 120 bytes above waiter
- NFDS ≥ 321: fd_set on heap (kvmalloc), not on stack at all

**Verdict**: ❌ DEAD — confirmed by NFDS sweep and FRONTEND_STACK_ALLOC=256 analysis.

### 2. sendmsg (analyzed 2026-07-14)

| Function | Frame | SP offset |
|----------|-------|-----------|
| `__arm64_sys_sendmsg` | 0x10 | stack_top - 0x10 |
| `__sys_sendmsg` | 0x1E0 | stack_top - 0x1F0 |
| `____sys_sendmsg` | 0x90 | stack_top - 0x280 |
| `selinux_socket_sendmsg` | 0x70 | stack_top - 0x2F0 |
| **Total (with selinux hook)** | **0x2F0** | |

**User data written by sendmsg chain**:

| Data | Location | User-controlled? |
|------|----------|-----------------|
| msghdr (56B) via `__copy_msghdr_from_user` | stack_top - 0x270 | ✅ Yes, but only reaches 0x270, waiter at 0x270 |
| cmsg via `____sys_sendmsg` (small ≤36B) | stack_top - 0x1E0 (v41) | ✅ Yes, but too high |
| cmsg via `____sys_sendmsg` (large >36B) | heap (kmalloc) | ❌ Not on stack |
| selinux security decision via `avc_has_perm` | stack_top - 0x280 (v7) | ❌ Kernel-controlled constants |

**Critical finding**: `selinux_socket_sendmsg` frame reaches waiter position (0x2F0 > 0x270), and `v8` at stack_top - 0x270 EXACTLY overlaps waiter's `tree_entry` field. But `v8 = &v11` (a stack pointer), NOT user-controlled data.

**Verdict**: ❌ DEAD — frame deep enough, but no user-controlled data at waiter position.

### 3. io_uring_setup (analyzed 2026-07-14)

| Function | Frame | SP offset |
|----------|-------|-----------|
| `__arm64_sys_io_uring_setup` | 0xA0 | stack_top - 0xA0 |
| `io_uring_create` | 0x70 | stack_top - 0x110 |
| **Total** | **0x110** | |

**User data**: 120 bytes copied via `copy_from_user` to stack_top - 0xA0. Way too shallow.
**io_uring_create** allocates io_uring_ctx (0x6C0 bytes) on heap via `kmem_cache_alloc_trace`, not stack.

**Verdict**: ❌ DEAD — total frame 0x110, waiter at 0x288. 0x178 byte gap.

### 4. binder (previously analyzed)

| Function | Frame |
|----------|-------|
| `binder_ioctl` | 0xD0 |
| `binder_ioctl_write_read` | 0x50 |
| `binder_thread_write` | 0x160 |
| **Total** | **0x280** |

User data: `copy_from_user` copies 48-byte `binder_write_read` struct to ~stack_top - 0x118.
Also: EACCES from shell user.

**Verdict**: ❌ DEAD — too shallow + permission denied.

### 5. poll (previously analyzed)

| Function | Frame |
|----------|-------|
| `__arm64_sys_poll` | 0x60 |
| `do_sys_poll` | 0x450 |
| **Total** | **0x4B0** |

User data: pollfd array is heap-allocated via kmalloc chain, not on stack.

**Verdict**: ❌ DEAD — user data on heap, not stack.

### 6. epoll_wait (previously analyzed)

| Function | Frame |
|----------|-------|
| `__arm64_sys_epoll_wait` | 0x10 |
| `do_epoll_wait` | 0xD0 |
| **Total** | **0xE0** |

**Verdict**: ❌ DEAD — only 0xE0, way too shallow.

### 7. sendmmsg (analyzed 2026-07-14) — CORRECTED

| Function | Frame | SP offset |
|----------|-------|-----------|
| `__arm64_sys_sendmmsg` | 0x10 | stack_top - 0x10 |
| `__sys_sendmmsg` | 0x2C0 | stack_top - 0x2D0 |
| `____sys_sendmsg` | 0x90 | stack_top - 0x360 |
| `selinux_socket_sendmsg` | 0x70 | stack_top - 0x3D0 |
| **Total (with selinux hook)** | **0x430** | |

**⚠️ CORRECTION**: Previous analysis confused v57 (pointer at stack_top - 0x2A8) with v69 (copy destination at stack_top - 0x240).

**User data written by sendmmsg chain**:

| Data | Location | User-controlled? | Gap to waiter |
|------|----------|-----------------|---------------|
| 28B mmsghdr via `copy_from_user` | stack_top - 0x240 (v69) | ✅ Yes | **112 bytes above** waiter end |
| msghdr (56B) via `__copy_msghdr_from_user` | stack_top - 0x100 (v91) | ✅ Yes | 368 bytes above waiter end |
| cmsg via `____sys_sendmsg` (small ≤36B) | stack_top - 0x350 (v41) | ✅ Yes | 80 bytes BELOW waiter start |
| selinux security decision | stack_top - 0x3D0 area | ❌ Kernel-controlled | Too low |

**Waiter struct layout** (IDA verified):
```
waiter.tree_entry:    stack_top - 0x300 to stack_top - 0x2E8
waiter.pi_tree_entry: stack_top - 0x2E8 to stack_top - 0x2D0
waiter.task:          stack_top - 0x2D0 to stack_top - 0x2C8
waiter.lock:          stack_top - 0x2C8 to stack_top - 0x2C0
waiter.prio:          stack_top - 0x2C0 to stack_top - 0x2BC
waiter.deadline:      stack_top - 0x2B8 to stack_top - 0x2B0
```

**Variable positions in __sys_sendmmsg** (IDA stack_frame verified):
- v56 (var_250): stack_top - 0x2C0 — within waiter.lock field, but kernel pointer
- v57 (var_238): stack_top - 0x2A8 — 8 bytes above waiter.end, pointer to v91
- v69 (var_1D0): stack_top - 0x240 — 112 bytes above waiter.end, COPY DESTINATION

**Verdict**: ❌ **DEAD** — 112-byte gap, not 8 bytes. No user-controlled data reaches waiter position.

---

## Summary: Syscall Stack Reachability

| Syscall | Total Frame | User Data Position | Reaches Waiter? | User-controlled? |
|---------|-------------|-------------------|-----------------|-----------------|
| pselect | 0x620 | stack_top - 0x210 | ❌ 120B above | ✅ Yes (fd_set) |
| sendmsg | 0x2F0 | stack_top - 0x270 (msghdr) | ❌ 0x18 above | ✅ Yes, but gap |
| sendmsg+selinux | 0x2F0 | stack_top - 0x280 (v7) | ✅ Yes (v8=0x288) | ❌ Kernel ptrs only |
| sendmmsg | 0x430 | stack_top - 0x240 (v69) | ❌ **112B above** | ✅ Yes (28B mmsghdr) |
| io_uring_setup | 0x110 | stack_top - 0xA0 | ❌ 0x1E8 above | ✅ Yes |
| binder | 0x280 | stack_top - 0x118 | ❌ 0x170 above | ✅ Yes |
| poll | 0x4B0 | heap | ❌ | ❌ Heap |
| epoll_wait | 0xE0 | too shallow | ❌ | ✅ Yes |

---

## Key Insight

**No known syscall writes user-controlled data to the waiter position (stack_top - 0x300 to stack_top - 0x2B0).**

The fundamental problem:
1. Syscalls with deep enough frames (pselect 0x620, poll 0x4B0) allocate user data on the HEAP, not the stack
2. Syscalls that do write to the stack (sendmmsg 0x240, sendmsg 0x270) don't reach deep enough
3. The closest user data is sendmmsg's 28-byte copy at stack_top - 0x240 — **112 bytes above** the waiter end
4. The only function that reaches the waiter position (selinux_socket_sendmsg) writes kernel-controlled data

---

## Possible Next Directions

### Direction A: Find a deeper syscall or different approach (HIGHEST PRIORITY)

The stack spray approach has been exhausted — no known syscall writes user-controlled data to the waiter position. The closest is sendmmsg at 112 bytes above.

Options:
1. **Search for other syscalls** — check `keyctl`, `recvmmsg`, `getsockopt`, `setsockopt` chains
2. **Use compiler-specific optimizations** — `-O2` vs `-Os` might change frame layouts
3. **Find a syscall that writes to the EXACT waiter position** — need to search more broadly

### Direction B: Use data already on the stack (no spray needed)

After GhostLock frees the waiter, the stack memory contains residual kernel pointers. If we can:
1. Leak the residual pointers (e.g., via KernelSnitch or pselect side-channel)
2. Calculate the waiter position from leaked pointers
3. Use the pi_blocked_on dangling pointer directly

This avoids the need for stack spray entirely.

### Direction C: Heap-based approach

Instead of overwriting the waiter on the stack, find a way to:
1. Spray the heap with a fake waiter struct
2. Make `pi_blocked_on` point to the heap spray

This requires finding a way to redirect `pi_blocked_on` to a heap address, which might not be possible with the current GhostLock trigger.

### Direction D: Redesign GhostLock trigger

The current trigger (FUTEX_CMP_REQUEUE_PI with 3 futex words + 3 threads) creates a specific stack layout. A different trigger might:
1. Place the waiter at a different offset
2. Use a different locking primitive that's more exploitable
3. Combine GhostLock with another vulnerability

---

## Recommendation

**Priority**: Direction A (find deeper syscall) > Direction B (no-spray approach) > Direction D (redesign) > Direction C (heap)

The stack spray approach is fundamentally limited by the fact that no syscall writes user-controlled data deep enough on the stack. Direction B (no-spray) might be the most promising alternative, as it avoids the stack spray problem entirely.
