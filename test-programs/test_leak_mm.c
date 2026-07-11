/*
 * test_leak_mm.c - 测试不同的 mm_struct 泄漏方法
 *
 * 方法:
 * 1. /proc/self/pagemap - 读取物理页映射
 * 2. /proc/self/smaps - 读取内存映射详情
 * 3. ASHMEM - Android 共享内存
 * 4. userfaultfd - 用户态缺页处理
 * 5. fork 时序 - 测量 fork 操作时序
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>

/* userfaultfd syscall */
#ifndef SYS_userfaultfd
#define SYS_userfaultfd 282
#endif

/* userfaultfd structures */
struct uffdio_api {
    uint64_t api;
    uint64_t features;
};
#define UFFDIO_API _IOWR(0xAA, 0, struct uffdio_api)

/* ASHMEM definitions */
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[256])
#define ASHMEM_GET_NAME _IOR(__ASHMEMIOC, 2, char[256])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE _IOR(__ASHMEMIOC, 4, size_t)

/* 测试 1: /proc/self/pagemap */
int test_pagemap(void) {
    printf("=== 测试 1: /proc/self/pagemap ===\n");

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        printf("  无法打开 /proc/self/pagemap: %s\n", strerror(errno));
        return -1;
    }

    /* 读取前几个页面的映射信息 */
    uint64_t buf[16];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0) {
        printf("  读取 %zd 字节\n", n);
        for (int i = 0; i < n / 8; i++) {
            printf("  [%d] = 0x%016llx\n", i, (unsigned long long)buf[i]);
        }
    }

    close(fd);
    return 0;
}

/* 测试 2: /proc/self/smaps */
int test_smaps(void) {
    printf("\n=== 测试 2: /proc/self/smaps ===\n");

    int fd = open("/proc/self/smaps", O_RDONLY);
    if (fd < 0) {
        printf("  无法打开 /proc/self/smaps: %s\n", strerror(errno));
        return -1;
    }

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        /* 只打印前 500 字符 */
        if (n > 500) {
            buf[500] = 0;
        }
        printf("  读取 %zd 字节\n", n);
        printf("  前 500 字符:\n%s\n", buf);
    }

    close(fd);
    return 0;
}

/* 测试 3: ASHMEM */
int test_ashmem(void) {
    printf("\n=== 测试 3: ASHMEM ===\n");

    int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("  无法打开 /dev/ashmem: %s\n", strerror(errno));
        return -1;
    }

    /* 设置 ashmem 名称 */
    const char *name = "test_leak_mm";
    ioctl(fd, ASHMEM_SET_NAME, name);

    /* 设置大小 */
    size_t size = 4096;
    ioctl(fd, ASHMEM_SET_SIZE, size);

    /* 映射内存 */
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        printf("  mmap 失败: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* 写入测试数据 */
    memset(ptr, 0x41, size);

    /* 读取 ashmem 名称 */
    char ashmem_name[256];
    ioctl(fd, ASHMEM_GET_NAME, ashmem_name);
    printf("  ashmem 名称: %s\n", ashmem_name);

    /* 读取 ashmem 大小 */
    size_t ashmem_size;
    ioctl(fd, ASHMEM_GET_SIZE, &ashmem_size);
    printf("  ashmem 大小: %zu\n", ashmem_size);

    /* 读取映射内容 */
    uint64_t *p = (uint64_t *)ptr;
    printf("  映射内容 (前 8 字节): 0x%016llx\n", (unsigned long long)p[0]);

    munmap(ptr, size);
    close(fd);
    return 0;
}

/* 测试 4: userfaultfd */
int test_userfaultfd(void) {
    printf("\n=== 测试 4: userfaultfd ===\n");

    int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        printf("  userfaultfd 失败: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    printf("  userfaultfd fd=%d\n", uffd);

    /* 设置 userfaultfd */
    struct uffdio_api api = {
        .api = 0xAA,
        .features = 0,
    };
    if (ioctl(uffd, UFFDIO_API, &api) < 0) {
        printf("  UFFDIO_API 失败: %s\n", strerror(errno));
        close(uffd);
        return -1;
    }

    printf("  userfaultfd API 版本: 0x%llx\n", (unsigned long long)api.api);

    close(uffd);
    return 0;
}

/* 测试 5: fork 时序 */
int test_fork_timing(void) {
    printf("\n=== 测试 5: fork 时序 ===\n");

    struct timeval start, end;
    int iterations = 100;

    /* 测量 fork 时序 */
    gettimeofday(&start, NULL);
    for (int i = 0; i < iterations; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(0);
        }
        waitpid(pid, NULL, 0);
    }
    gettimeofday(&end, NULL);

    long elapsed = (end.tv_sec - start.tv_sec) * 1000000 +
                   (end.tv_usec - start.tv_usec);
    printf("  %d 次 fork 耗时: %ld 微秒 (平均 %ld 微秒/次)\n",
           iterations, elapsed, elapsed / iterations);

    return 0;
}

/* 测试 6: /proc/self/maps */
int test_maps(void) {
    printf("\n=== 测试 6: /proc/self/maps ===\n");

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        printf("  无法打开 /proc/self/maps: %s\n", strerror(errno));
        return -1;
    }

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        printf("  读取 %zd 字节\n", n);
        /* 只打印前 20 行 */
        int lines = 0;
        char *p = buf;
        while (*p && lines < 20) {
            putchar(*p);
            if (*p == '\n') lines++;
            p++;
        }
    }

    close(fd);
    return 0;
}

int main(void) {
    printf("=== mm_struct 泄漏方法测试 ===\n");
    printf("PID: %d\n\n", getpid());

    test_pagemap();
    test_smaps();
    test_ashmem();
    test_userfaultfd();
    test_fork_timing();
    test_maps();

    printf("\n=== 测试完成 ===\n");
    return 0;
}
