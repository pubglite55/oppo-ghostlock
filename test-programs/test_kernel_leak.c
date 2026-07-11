/*
 * test_kernel_leak.c - 测试各种内核信息泄漏方法
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

/* 测试 1: uname - 内核版本信息 */
int test_uname(void) {
    printf("=== 1. uname ===\n");
    struct utsname buf;
    if (uname(&buf) == 0) {
        printf("  sysname: %s\n", buf.sysname);
        printf("  nodename: %s\n", buf.nodename);
        printf("  release: %s\n", buf.release);
        printf("  version: %s\n", buf.version);
        printf("  machine: %s\n", buf.machine);
    }
    return 0;
}

/* 测试 2: /proc/version */
int test_proc_version(void) {
    printf("\n=== 2. /proc/version ===\n");
    int fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 3: /proc/sys/kernel/随机值 */
int test_random(void) {
    printf("\n=== 3. /proc/sys/kernel/random ===\n");
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  boot_id: %s", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 4: /proc/self/stat */
int test_proc_stat(void) {
    printf("\n=== 4. /proc/self/stat ===\n");
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 5: /proc/self/status */
int test_proc_status(void) {
    printf("\n=== 5. /proc/self/status ===\n");
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            /* 只打印前 500 字符 */
            if (n > 500) buf[500] = 0;
            printf("  %s\n", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 6: /proc/self/maps */
int test_proc_maps(void) {
    printf("\n=== 6. /proc/self/maps ===\n");
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  读取 %zd 字节\n", n);
        }
        close(fd);
    }
    return 0;
}

/* 测试 7: /proc/self/pagemap */
int test_pagemap(void) {
    printf("\n=== 7. /proc/self/pagemap ===\n");
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd >= 0) {
        uint64_t buf[64];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            printf("  读取 %zd 字节\n", n);
            /* 检查是否有非零值 */
            int nonzero = 0;
            for (int i = 0; i < n / 8; i++) {
                if (buf[i] != 0) nonzero++;
            }
            printf("  非零条目: %d/%d\n", nonzero, (int)(n / 8));
            if (nonzero > 0) {
                for (int i = 0; i < n / 8 && i < 10; i++) {
                    if (buf[i] != 0) {
                        printf("  [%d] = 0x%016llx\n", i, (unsigned long long)buf[i]);
                    }
                }
            }
        }
        close(fd);
    }
    return 0;
}

/* 测试 8: /proc/self/smaps */
int test_smaps(void) {
    printf("\n=== 8. /proc/self/smaps ===\n");
    int fd = open("/proc/self/smaps", O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  读取 %zd 字节\n", n);
        }
        close(fd);
    }
    return 0;
}

/* 测试 9: /proc/self/statm */
int test_statm(void) {
    printf("\n=== 9. /proc/self/statm ===\n");
    int fd = open("/proc/self/statm", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 10: /proc/self/cmdline */
int test_cmdline(void) {
    printf("\n=== 10. /proc/self/cmdline ===\n");
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            /* 将 \0 替换为空格 */
            for (int i = 0; i < n; i++) {
                if (buf[i] == 0) buf[i] = ' ';
            }
            printf("  %s\n", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 11: /proc/self/environ */
int test_environ(void) {
    printf("\n=== 11. /proc/self/environ ===\n");
    int fd = open("/proc/self/environ", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  读取 %zd 字节\n", n);
        }
        close(fd);
    } else {
        printf("  无法打开: %s\n", strerror(errno));
    }
    return 0;
}

/* 测试 12: /proc/self/limits */
int test_limits(void) {
    printf("\n=== 12. /proc/self/limits ===\n");
    int fd = open("/proc/self/limits", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 13: /proc/self/attr */
int test_attr(void) {
    printf("\n=== 13. /proc/self/attr/current ===\n");
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        }
        close(fd);
    }
    return 0;
}

/* 测试 14: sysinfo */
int test_sysinfo(void) {
    printf("\n=== 14. sysinfo ===\n");
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        printf("  uptime: %ld seconds\n", info.uptime);
        printf("  totalram: %lu\n", info.totalram);
        printf("  freeram: %lu\n", info.freeram);
        printf("  sharedram: %lu\n", info.sharedram);
        printf("  bufferram: %lu\n", info.bufferram);
        printf("  totalswap: %lu\n", info.totalswap);
        printf("  procs: %d\n", info.procs);
    }
    return 0;
}

/* 测试 15: clock_gettime */
int test_clock(void) {
    printf("\n=== 15. clock_gettime ===\n");
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("  CLOCK_MONOTONIC: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
    clock_gettime(CLOCK_REALTIME, &ts);
    printf("  CLOCK_REALTIME: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
    return 0;
}

int main(void) {
    printf("=== 内核信息泄漏测试 ===\n");
    printf("PID: %d\n\n", getpid());

    test_uname();
    test_proc_version();
    test_random();
    test_proc_stat();
    test_proc_status();
    test_proc_maps();
    test_pagemap();
    test_smaps();
    test_statm();
    test_cmdline();
    test_environ();
    test_limits();
    test_attr();
    test_sysinfo();
    test_clock();

    printf("\n=== 测试完成 ===\n");
    return 0;
}
