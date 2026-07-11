/*
 * test_improved_timing.c - 改进的时序测量方法
 * 
 * 1. 增加测量次数 (10000+)
 * 2. 使用更复杂的统计分析
 * 3. 尝试不同的 syscall 组合
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <errno.h>

#define MEASUREMENTS 10000
#define WARMUP 1000

static inline uint64_t rdtsc(void) {
    uint64_t val;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    asm volatile("isb" ::: "memory");
    return val;
}

// 排序数组
static void sort_array(uint32_t *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[i] > arr[j]) {
                uint32_t tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
}

// 计算标准差
static double calc_stddev(uint64_t *arr, int n, uint64_t mean) {
    double sum = 0;
    for (int i = 0; i < n; i++) {
        double diff = (double)arr[i] - (double)mean;
        sum += diff * diff;
    }
    return sqrt(sum / n);
}

// 测试 1: 增加 futex 操作次数
static void test_futex_timing(void) {
    printf("=== 1. Futex 时序 (大量测量) ===\n");

    uint32_t futex_val = 0;
    struct timespec timeout = {0, 0};
    uint32_t *futex_addr = &futex_val;

    uint32_t *times = malloc(MEASUREMENTS * sizeof(uint32_t));
    if (!times) return;

    // 预热
    for (int i = 0; i < WARMUP; i++) {
        syscall(SYS_futex, futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
    }

    // 测量 FUTEX_WAKE 时序
    for (int i = 0; i < MEASUREMENTS; i++) {
        uint64_t start = rdtsc();
        syscall(SYS_futex, futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
        uint64_t end = rdtsc();
        times[i] = (uint32_t)(end - start);
    }

    // 统计
    sort_array(times, MEASUREMENTS);
    uint64_t sum = 0;
    for (int i = 0; i < MEASUREMENTS; i++) {
        sum += times[i];
    }

    printf("  测量次数: %d\n", MEASUREMENTS);
    printf("  最小值: %u\n", times[0]);
    printf("  最大值: %u\n", times[MEASUREMENTS - 1]);
    printf("  中位数: %u\n", times[MEASUREMENTS / 2]);
    printf("  平均值: %lu\n", sum / MEASUREMENTS);
    printf("  P1: %u\n", times[MEASUREMENTS / 100]);
    printf("  P5: %u\n", times[MEASUREMENTS / 20]);
    printf("  P95: %u\n", times[MEASUREMENTS * 95 / 100]);
    printf("  P99: %u\n", times[MEASUREMENTS * 99 / 100]);

    free(times);
}

// 测试 2: 不同 futex 操作的时序
static void test_different_futex_ops(void) {
    printf("\n=== 2. 不同 Futex 操作时序 ===\n");

    uint32_t futex_val = 0;
    struct timespec timeout = {0, 0};

    // 测试 FUTEX_WAKE
    uint32_t times_wake[MEASUREMENTS];
    for (int i = 0; i < MEASUREMENTS; i++) {
        uint64_t start = rdtsc();
        syscall(SYS_futex, &futex_val, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
        uint64_t end = rdtsc();
        times_wake[i] = (uint32_t)(end - start);
    }

    // 测试 FUTEX_WAIT (会立即返回)
    uint32_t times_wait[MEASUREMENTS];
    for (int i = 0; i < MEASUREMENTS; i++) {
        futex_val = 1;  // 设置非零值，使 WAIT 立即返回
        uint64_t start = rdtsc();
        syscall(SYS_futex, &futex_val, FUTEX_WAIT_PRIVATE, 0, &timeout, NULL, 0);
        uint64_t end = rdtsc();
        times_wait[i] = (uint32_t)(end - start);
    }

    // 测试 FUTEX_CMP_REQUEUE
    uint32_t times_requeue[MEASUREMENTS];
    uint32_t futex2 = 0;
    for (int i = 0; i < MEASUREMENTS; i++) {
        uint64_t start = rdtsc();
        syscall(SYS_futex, &futex_val, FUTEX_CMP_REQUEUE_PRIVATE, 0,
                (void *)1, &futex2, 0);
        uint64_t end = rdtsc();
        times_requeue[i] = (uint32_t)(end - start);
    }

    // 统计
    sort_array(times_wake, MEASUREMENTS);
    sort_array(times_wait, MEASUREMENTS);
    sort_array(times_requeue, MEASUREMENTS);

    printf("  FUTEX_WAKE:     P50=%u P99=%u\n",
           times_wake[MEASUREMENTS / 2], times_wake[MEASUREMENTS * 99 / 100]);
    printf("  FUTEX_WAIT:     P50=%u P99=%u\n",
           times_wait[MEASUREMENTS / 2], times_wait[MEASUREMENTS * 99 / 100]);
    printf("  FUTEX_CMP_REQUEUE: P50=%u P99=%u\n",
           times_requeue[MEASUREMENTS / 2], times_requeue[MEASUREMENTS * 99 / 100]);
}

// 测试 3: 不同 syscall 的时序
static void test_syscall_timing(void) {
    printf("\n=== 3. 不同 Syscall 时序 ===\n");

    uint32_t times_getpid[MEASUREMENTS];
    uint32_t times_gettid[MEASUREMENTS];
    uint32_t times_write[MEASUREMENTS];

    for (int i = 0; i < MEASUREMENTS; i++) {
        uint64_t start, end;

        // getpid
        start = rdtsc();
        syscall(SYS_getpid);
        end = rdtsc();
        times_getpid[i] = (uint32_t)(end - start);

        // gettid
        start = rdtsc();
        syscall(SYS_gettid);
        end = rdtsc();
        times_gettid[i] = (uint32_t)(end - start);

        // write (到 /dev/null)
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            char buf = 'x';
            start = rdtsc();
            write(fd, &buf, 1);
            end = rdtsc();
            times_write[i] = (uint32_t)(end - start);
            close(fd);
        }
    }

    sort_array(times_getpid, MEASUREMENTS);
    sort_array(times_gettid, MEASUREMENTS);
    sort_array(times_write, MEASUREMENTS);

    printf("  getpid:     P50=%u P99=%u\n",
           times_getpid[MEASUREMENTS / 2], times_getpid[MEASUREMENTS * 99 / 100]);
    printf("  gettid:     P50=%u P99=%u\n",
           times_gettid[MEASUREMENTS / 2], times_gettid[MEASUREMENTS * 99 / 100]);
    printf("  write:      P50=%u P99=%u\n",
           times_write[MEASUREMENTS / 2], times_write[MEASUREMENTS * 99 / 100]);
}

// 测试 4: 时序稳定性测试
static void test_timing_stability(void) {
    printf("\n=== 4. 时序稳定性测试 ===\n");

    uint32_t times[MEASUREMENTS];

    for (int i = 0; i < MEASUREMENTS; i++) {
        uint64_t start = rdtsc();
        syscall(SYS_getpid);
        uint64_t end = rdtsc();
        times[i] = (uint32_t)(end - start);
    }

    // 计算统计量
    sort_array(times, MEASUREMENTS);
    uint64_t sum = 0;
    for (int i = 0; i < MEASUREMENTS; i++) {
        sum += times[i];
    }
    uint64_t mean = sum / MEASUREMENTS;

    // 计算标准差
    double variance = 0;
    for (int i = 0; i < MEASUREMENTS; i++) {
        double diff = (double)times[i] - (double)mean;
        variance += diff * diff;
    }
    double stddev = sqrt(variance / MEASUREMENTS);

    // 计算变异系数
    double cv = stddev / mean * 100;

    printf("  平均值: %lu\n", mean);
    printf("  标准差: %.2f\n", stddev);
    printf("  变异系数: %.2f%%\n", cv);
    printf("  最小值: %u\n", times[0]);
    printf("  最大值: %u\n", times[MEASUREMENTS - 1]);
    printf("  范围: %u\n", times[MEASUREMENTS - 1] - times[0]);
}

#include <fcntl.h>
#include <sys/stat.h>

int main(void) {
    printf("=== 改进的时序测量方法 ===\n");
    printf("PID: %d\n\n", getpid());

    test_futex_timing();
    test_different_futex_ops();
    test_syscall_timing();
    test_timing_stability();

    printf("\n=== 测试完成 ===\n");
    return 0;
}
