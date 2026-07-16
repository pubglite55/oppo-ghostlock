# Route 2: No-Spray Approach Analysis

**Date**: 2026-07-14
**Goal**: Exploit GhostLock without stack spray by using residual data at the waiter position

---

## Waiter Position Residual Data

After `futex_wait_requeue_pi` returns, the waiter struct on the kernel stack contains:

| Field | Offset | Value | Exploitation Value |
|-------|--------|-------|-------------------|
| tree_entry | stack_top - 0x300 | rb_node with kernel pointers | Medium - leakable rt_mutex pointers |
| pi_tree_entry | stack_top - 0x2E8 | rb_node (may be zeroed) | Low |
| task | stack_top - 0x2D0 | pointer to current task_struct | **High** - leakable task_struct address |
| lock | stack_top - 0x2C8 | pointer to futex rt_mutex_base | **High** - leakable futex address |
| prio | stack_top - 0x2C0 | current priority (e.g., 120) | Low |
| deadline | stack_top - 0x2B8 | current deadline | Low |

## The Fundamental Problem

The residual data contains **kernel pointers** (task, lock, rb_node links) that could be valuable for exploitation. However:

1. **We cannot READ kernel stack from userspace** — the kernel stack is not accessible via /proc, /sys, or any syscall
2. **kptr_restrict is enforced** — /proc/kallsyms is denied
3. **No syscall reads kernel stack data** — all data-copying syscalls copy FROM userspace, not TO userspace from kernel stack

## Possible Approaches

### Approach A: Extend KernelSnitch to Leak Stack Addresses

KernelSnitch already leaks mm_struct addresses from the slab via timing side-channels. Could we extend it to leak stack addresses?

**Challenge**: KernelSnitch works by detecting futex hash collisions in slab memory. The kernel stack is NOT in the slab — it's a separate memory region allocated by the kernel. The timing characteristics are different.

**Feasibility**: Low — requires fundamentally different technique than KernelSnitch.

### Approach B: Side-Channel to Read Stack Data

Find a side-channel that reveals data at the waiter position.

**Options**:
1. **Cache timing** — measure access time to specific stack addresses
2. **Branch prediction** — use conditional branches to leak data
3. **Speculative execution** — use Spectre-like techniques

**Challenge**: All of these require some way to make the kernel access the waiter position and observe the result. But the kernel doesn't naturally access the waiter position after the function returns.

**Feasibility**: Very Low — requires novel side-channel research.

### Approach C: Use pi_blocked_on to Trigger Kernel Read

The `pi_blocked_on` pointer in the task struct still points to the waiter position. If we can make the kernel dereference this pointer, it might read data from the waiter.

**Options**:
1. Trigger `rt_mutex_adjust_prio` — this reads through `pi_blocked_on`
2. Trigger PI chain walk — this traverses the waiter chain
3. Trigger futex operations — this might access `pi_blocked_on`

**Challenge**: The kernel's PI code is designed to handle valid waiter pointers. If the waiter is freed, the PI code might crash or behave unpredictably.

**Feasibility**: Medium — but requires precise control over kernel execution.

### Approach D: Accept Limitation and Move to Other Routes

The no-spray approach is fundamentally limited by:
1. We can't read kernel stack from userspace
2. We can't control the waiter contents without writing to the stack
3. The residual data is just kernel pointers, which we can't use directly

**Recommendation**: Move to Route 3 (redesign GhostLock trigger) or Route 4 (heap-based approach).

## Conclusion

The no-spray approach is **not viable** with the current vulnerability. The fundamental problem is that the waiter is on the kernel stack, and we can't write to or read from the kernel stack from userspace.

The residual data at the waiter position contains kernel pointers that could be valuable, but we have no way to leak or use them without a novel side-channel technique.

## Next Steps

1. **Route 3**: Redesign GhostLock trigger to use a different locking primitive
2. **Route 4**: Explore heap-based approaches
3. **Route 1**: Search for more syscalls (keyctl, setsockopt) — low priority
4. **Novel research**: Develop a side-channel to leak kernel stack data — very high effort
