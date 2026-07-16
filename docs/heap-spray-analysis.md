# Heap Spray Approach Analysis

**Date**: 2026-07-14
**Goal**: Use heap spray instead of stack spray to exploit GhostLock

---

## GhostLock Vulnerability Recap

After GhostLock triggers:
1. `current->pi_blocked_on` points to the freed waiter on the kernel stack
2. The waiter struct contains: task, lock, prio, deadline fields
3. If the kernel dereferences `pi_blocked_on`, it reads the freed waiter memory

## Heap Spray Exploitation Chain

```
Step 1: Leak mm_struct address (KernelSnitch) ✅ DONE
Step 2: Calculate task_struct address from mm_struct
Step 3: Trigger GhostLock → dangling pi_blocked_on pointer
Step 4: Spray heap with fake waiter structs (sk_buff reclaim) ✅ DONE
Step 5: Use pipe physical read/write to write to task_struct
Step 6: Change pi_blocked_on to point to sprayed heap address
Step 7: Trigger PI operation → kernel reads fake waiter
```

## Step-by-Step Analysis

### Step 2: Calculate task_struct Address

The task_struct and mm_struct are related:
```
task_struct->mm = mm_struct address
```

But the offset between them depends on the kernel version and configuration. We need to find the offset using pahole or IDA.

From target.h:
```
#define MM_OWNER_OFF 1032  // offset of mm->owner in mm_struct
```

The `mm->owner` field points back to the task_struct. So:
```
task_struct = *(mm_struct + MM_OWNER_OFF)
```

If we can read the mm_struct (which we leaked), we can find the task_struct.

**Challenge**: We need a READ primitive to read mm_struct->owner. The pipe physical read/write can do this.

### Step 3: Trigger GhostLock

Already implemented in the exploit code. Uses FUTEX_CMP_REQUEUE_PI with 3 futex words + 3 threads.

After this step:
- `current->pi_blocked_on` points to the freed waiter on the stack
- The waiter memory is "freed" but still accessible

### Step 4: Spray Heap with Fake Waiter

The exploit already has sk_buff reclaim (4/4 send success). We need to:
1. Spray the heap with fake waiter structs
2. Each fake waiter should contain controlled pointers:
   - task: pointer to a fake task_struct (or the real one)
   - lock: pointer to a fake rt_mutex_base
   - prio: controlled priority value
   - deadline: controlled deadline value

### Step 5-6: Write to task_struct and Change pi_blocked_on

Using the pipe physical read/write:
1. Read mm_struct->owner to get task_struct address
2. Write to task_struct->pi_blocked_on to point to the sprayed heap address

**Key offset**: `pi_blocked_on` offset in task_struct needs to be determined.

From the knowledge notes:
```
#define TASK_PID_OFF 0x618
#define TASK_TGID_OFF 0x61c
#define TASK_TASKS_OFF 0x550
```

But `pi_blocked_on` offset is not in target.h. We need to find it using pahole or IDA.

### Step 7: Trigger PI Operation

After changing `pi_blocked_on`, we need to trigger code that reads through it:
1. Call `rt_mutex_adjust_prio` or similar
2. The kernel reads the fake waiter from the sprayed heap
3. The fake waiter contains controlled pointers
4. The kernel uses these pointers to read/write memory

## Key Challenges

### Challenge 1: Find pi_blocked_on Offset

We need the exact offset of `pi_blocked_on` in task_struct. This can be found using:
- pahole on the target kernel
- IDA analysis of the kernel binary
- KASLR bypass + direct reading

### Challenge 2: Time the Operations Correctly

The exploitation sequence must be:
1. Leak mm_struct (KernelSnitch) — before GhostLock
2. Trigger GhostLock — creates dangling pointer
3. Spray heap — before kernel accesses pi_blocked_on
4. Write to task_struct — before kernel accesses pi_blocked_on
5. Trigger PI operation — after changing pi_blocked_on

If the kernel accesses `pi_blocked_on` before we change it, it will read the freed waiter memory and likely crash.

### Challenge 3: Avoid Kernel Crash

After GhostLock triggers, the kernel might try to access `pi_blocked_on` during:
- Priority adjustment
- PI chain walk
- Error handling

We need to ensure the kernel doesn't access `pi_blocked_on` until we've changed it.

## Existing Exploit Capabilities

| Capability | Status | Notes |
|------------|--------|-------|
| KernelSnitch mm_struct leak | ✅ Done | mm_struct=0xffffff89807912c0 |
| sk_buff reclaim | ✅ Done | 4/4 send success |
| pipe physical read/write | ⏳ Pending | Needs mm_struct for physical address calculation |
| KASLR bypass | ✅ Done | kernel base known |

## What We Need

1. **pi_blocked_on offset in task_struct** — need pahole or IDA analysis
2. **Physical address calculation** — mm_struct → physical address → task_struct physical address
3. **Timing control** — ensure kernel doesn't access pi_blocked_on before we change it

## Feasibility Assessment

| Factor | Assessment |
|--------|------------|
| Technical feasibility | Medium — all pieces exist, but timing is critical |
| Implementation complexity | High — requires precise coordination of multiple steps |
| Risk of kernel crash | High — if timing is wrong, kernel will panic |
| Novelty | Medium — heap spray is well-known, but applying it to GhostLock is new |

## Conclusion

The heap spray approach is **technically feasible** but requires:
1. Finding the `pi_blocked_on` offset in task_struct
2. Implementing the physical address calculation chain
3. Precise timing control to avoid kernel crashes

This is the most promising approach among all the alternatives analyzed.

## Next Steps

1. Find `pi_blocked_on` offset using pahole or IDA
2. Implement the task_struct address calculation
3. Test the timing control mechanism
4. Build a proof-of-concept exploitation chain
