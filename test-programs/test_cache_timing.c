/*
 * test_cache_timing.c - Cache-based 时序攻击测试
 * 
 * 使用 Prime+Probe 方法测量缓存访问时序
 * 不受 KPTI 影响
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>

#define CACHE_LINE_SIZE 64
#define NUM_PROBES 1000
#define STRIDE 4096

// 读取 CPU 周期计数器 (ARM64)
static inline uint64_t rdtsc(void) {
    uint64_t val;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    asm volatile("isb" ::: "memory");
    return val;
}

// 测量内存访问时间
static uint64_t measure_access_time(volatile char *addr) {
    uint64_t start, end;
    start = rdtsc();
    volatile char tmp = *addr;
    end = rdtsc();
    return end - start;
}

// Prime: 预填充缓存
static void prime_cache(volatile char *base, int size) {
    for (int i = 0; i < size; i += CACHE_LINE_SIZE) {
        volatile char tmp = base[i];
        (void)tmp;
    }
}

// Probe: 测量缓存访问时间
static uint64_t probe_cache(volatile char *base, int size) {
    uint64_t total = 0;
    for (int i = 0; i < size; i += CACHE_LINE_SIZE) {
        uint64_t start = rdtsc();
        volatile char tmp = base[i];
        uint64_t end = rdtsc();
        total += (end - start);
    }
    return total / (size / CACHE_LINE_SIZE);
}

// 测试 1: 基本缓存时序
static void test_basic_cache_timing(void) {
    printf("=== 1. 基本缓存时序 ===\n");

    // 分配内存
    int size = 64 * 1024;  // 64KB
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        printf("  mmap 失败\n");
        return;
    }

    // 填充内存
    memset(mem, 0x41, size);

    // 测量冷缓存访问
    uint64_t cold_times[NUM_PROBES];
    for (int i = 0; i < NUM_PROBES; i++) {
        cold_times[i] = measure_access_time(&mem[i * STRIDE % size]);
    }

    // 测量热缓存访问
    uint64_t hot_times[NUM_PROBES];
    prime_cache(mem, size);
    for (int i = 0; i < NUM_PROBES; i++) {
        hot_times[i] = measure_access_time(&mem[i * STRIDE % size]);
    }

    // 统计
    uint64_t cold_sum = 0, hot_sum = 0;
    for (int i = 0; i < NUM_PROBES; i++) {
        cold_sum += cold_times[i];
        hot_sum += hot_times[i];
    }

    printf("  冷缓存平均: %lu ticks\n", cold_sum / NUM_PROBES);
    printf("  热缓存平均: %lu ticks\n", hot_sum / NUM_PROBES);
    printf("  差异: %lu ticks\n", (cold_sum - hot_sum) / NUM_PROBES);

    munmap(mem, size);
}

// 测试 2: Prime+Probe
static void test_prime_probe(void) {
    printf("\n=== 2. Prime+Probe ===\n");

    int cache_size = 32 * 1024;  // 32KB (L1 cache)
    int probe_count = 100;

    char *mem = mmap(NULL, cache_size * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        printf("  mmap 失败\n");
        return;
    }

    memset(mem, 0x41, cache_size * 2);

    // Prime: 填充目标缓存
    prime_cache(mem, cache_size);

    // Probe: 测量访问时间
    uint64_t times[probe_count];
    for (int i = 0; i < probe_count; i++) {
        times[i] = probe_cache(mem, cache_size);
    }

    // 统计
    uint64_t sum = 0;
    for (int i = 0; i < probe_count; i++) {
        sum += times[i];
    }

    printf("  缓存大小: %d bytes\n", cache_size);
    printf("  探测次数: %d\n", probe_count);
    printf("  平均访问时间: %lu ticks\n", sum / probe_count);

    munmap(mem, cache_size * 2);
}

// 测试 3: 不同内存区域的时序差异
static void test_memory_regions(void) {
    printf("\n=== 3. 不同内存区域时序 ===\n");

    // 测试栈、堆、mmap
    int stack_var = 0;
    char *heap_mem = malloc(4096);
    char *mmap_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    memset(heap_mem, 0x41, 4096);
    memset(mmap_mem, 0x41, 4096);

    printf("  栈: %lu ticks\n", measure_access_time((char *)&stack_var));
    printf("  堆: %lu ticks\n", measure_access_time(heap_mem));
    printf("  mmap: %lu ticks\n", measure_access_time(mmap_mem));

    free(heap_mem);
    munmap(mmap_mem, 4096);
}

// 测试 4: 多次测量取中位数
static void test_statistical_timing(void) {
    printf("\n=== 4. 统计时序分析 ===\n");

    int size = 4096;
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        printf("  mmap 失败\n");
        return;
    }

    memset(mem, 0x41, size);

    // 测量 10000 次
    int iterations = 10000;
    uint64_t *times = malloc(iterations * sizeof(uint64_t));

    for (int i = 0; i < iterations; i++) {
        // 随机偏移访问
        int offset = (i * 137) % size;
        times[i] = measure_access_time(&mem[offset]);
    }

    // 排序
    for (int i = 0; i < iterations - 1; i++) {
        for (int j = i + 1; j < iterations; j++) {
            if (times[i] > times[j]) {
                uint64_t tmp = times[i];
                times[i] = times[j];
                times[j] = tmp;
            }
        }
    }

    // 统计
    uint64_t sum = 0;
    for (int i = 0; i < iterations; i++) {
        sum += times[i];
    }

    printf("  测量次数: %d\n", iterations);
    printf("  最小值: %lu\n", times[0]);
    printf("  最大值: %lu\n", times[iterations - 1]);
    printf("  中位数: %lu\n", times[iterations / 2]);
    printf("  平均值: %lu\n", sum / iterations);
    printf("  P99: %lu\n", times[iterations * 99 / 100]);

    free(times);
    munmap(mem, size);
}

int main(void) {
    printf("=== Cache-based 时序攻击测试 ===\n");
    printf("PID: %d\n\n", getpid());

    test_basic_cache_timing();
    test_prime_probe();
    test_memory_regions();
    test_statistical_timing();

    printf("\n=== 测试完成 ===\n");
    return 0;
}
