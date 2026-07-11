/*
 * test_auxv_leak.c - 通过辅助向量泄漏内核信息
 * 
 * 尝试从 /proc/self/auxv 获取内核地址
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

// 辅助向量类型定义
#define AT_NULL         0
#define AT_PHDR         3
#define AT_PHENT        4
#define AT_PHNUM        5
#define AT_PAGESZ       6
#define AT_BASE         7
#define AT_ENTRY        9
#define AT_UID          11
#define AT_GID          12
#define AT_EUID         13
#define AT_EGID         14
#define AT_SECURE       23
#define AT_RANDOM        25
#define AT_HWCAP         16
#define AT_HWCAP2        26
#define AT_EXECFN        31
#define AT_PLATFORM      15
#define AT_SYSINFO_EHDR 33
#define AT_SYSINFO       32
#define AT_L1I_CACHESHAPE 34
#define AT_L1D_CACHESHAPE 35
#define AT_L2_CACHESHAPE  36
#define AT_L3_CACHESHAPE  37

// 辅助向量结构
struct auxv_entry {
    uint64_t type;
    uint64_t value;
};

// 获取辅助向量类型名称
const char *get_auxv_type_name(uint64_t type) {
    switch (type) {
        case AT_NULL: return "AT_NULL";
        case AT_PHDR: return "AT_PHDR";
        case AT_PHENT: return "AT_PHENT";
        case AT_PHNUM: return "AT_PHNUM";
        case AT_PAGESZ: return "AT_PAGESZ";
        case AT_BASE: return "AT_BASE";
        case AT_ENTRY: return "AT_ENTRY";
        case AT_UID: return "AT_UID";
        case AT_GID: return "AT_GID";
        case AT_EUID: return "AT_EUID";
        case AT_EGID: return "AT_EGID";
        case AT_SECURE: return "AT_SECURE";
        case AT_RANDOM: return "AT_RANDOM";
        case AT_HWCAP: return "AT_HWCAP";
        case AT_HWCAP2: return "AT_HWCAP2";
        case AT_EXECFN: return "AT_EXECFN";
        case AT_PLATFORM: return "AT_PLATFORM";
        case AT_SYSINFO_EHDR: return "AT_SYSINFO_EHDR";
        case AT_SYSINFO: return "AT_SYSINFO";
        case AT_L1I_CACHESHAPE: return "AT_L1I_CACHESHAPE";
        case AT_L1D_CACHESHAPE: return "AT_L1D_CACHESHAPE";
        case AT_L2_CACHESHAPE: return "AT_L2_CACHESHAPE";
        case AT_L3_CACHESHAPE: return "AT_L3_CACHESHAPE";
        default: return "UNKNOWN";
    }
}

// 测试 1: 读取 /proc/self/auxv
static void test_proc_auxv(void) {
    printf("=== 1. /proc/self/auxv ===\n");

    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) {
        printf("  无法打开: %s\n", strerror(errno));
        return;
    }

    struct auxv_entry auxv[64];
    ssize_t n = read(fd, auxv, sizeof(auxv));
    close(fd);

    if (n <= 0) {
        printf("  读取失败\n");
        return;
    }

    printf("  读取 %zd 字节\n", n);
    int count = n / sizeof(struct auxv_entry);

    for (int i = 0; i < count; i++) {
        if (auxv[i].type == AT_NULL) break;

        printf("  [%2d] %s (0x%lx) = 0x%lx",
               i, get_auxv_type_name(auxv[i].type),
               auxv[i].type, auxv[i].value);

        // 检查是否像内核地址
        if (auxv[i].value > 0xffffffc000000000ULL &&
            auxv[i].value < 0xffffffffffffffffULL) {
            printf(" ← 可能是内核地址!");
        }
        printf("\n");
    }
}

// 测试 2: 检查 AT_SYSINFO_EHDR (vDSO 地址)
static void test_vdso(void) {
    printf("\n=== 2. vDSO 地址 ===\n");

    extern char **environ;
    char *auxv = (char *)environ;

    // 跳过环境变量
    while (*auxv) auxv++;
    auxv++;  // 跳过 NULL

    struct auxv_entry *entry = (struct auxv_entry *)auxv;
    while (entry->type != AT_NULL) {
        if (entry->type == AT_SYSINFO_EHDR) {
            printf("  vDSO 地址: 0x%lx\n", entry->value);
            printf("  vDSO 可能是内核映射的用户态部分\n");

            // 尝试读取 vDSO 内容
            uint8_t *vdso = (uint8_t *)entry->value;
            printf("  vDSO 前 16 字节: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", vdso[i]);
            }
            printf("\n");
        }
        entry++;
    }
}

// 测试 3: 检查 AT_RANDOM
static void test_random(void) {
    printf("\n=== 3. AT_RANDOM ===\n");

    extern char **environ;
    char *auxv = (char *)environ;

    while (*auxv) auxv++;
    auxv++;

    struct auxv_entry *entry = (struct auxv_entry *)auxv;
    while (entry->type != AT_NULL) {
        if (entry->type == AT_RANDOM) {
            printf("  AT_RANDOM 地址: 0x%lx\n", entry->value);

            // 读取随机值
            uint8_t *random = (uint8_t *)entry->value;
            printf("  随机值: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", random[i]);
            }
            printf("\n");
        }
        entry++;
    }
}

// 测试 4: 检查 AT_BASE (动态链接器)
static void test_base(void) {
    printf("\n=== 4. AT_BASE (动态链接器) ===\n");

    extern char **environ;
    char *auxv = (char *)environ;

    while (*auxv) auxv++;
    auxv++;

    struct auxv_entry *entry = (struct auxv_entry *)auxv;
    while (entry->type != AT_NULL) {
        if (entry->type == AT_BASE) {
            printf("  动态链接器地址: 0x%lx\n", entry->value);
        }
        entry++;
    }
}

// 测试 5: 读取 /proc/self/maps 寻找内核映射
static void test_proc_maps(void) {
    printf("\n=== 5. /proc/self/maps 内核映射 ===\n");

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        printf("  无法打开\n");
        return;
    }

    char buf[16384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return;
    buf[n] = 0;

    // 查找可能的内核映射
    char *line = strtok(buf, "\n");
    while (line) {
        // 查找 [vdso] 或 [vsyscall]
        if (strstr(line, "[vdso]") || strstr(line, "[vsyscall]")) {
            printf("  %s\n", line);
        }
        line = strtok(NULL, "\n");
    }
}

#include <errno.h>

int main(void) {
    printf("=== 辅助向量内核信息泄漏测试 ===\n");
    printf("PID: %d\n\n", getpid());

    test_proc_auxv();
    test_vdso();
    test_random();
    test_base();
    test_proc_maps();

    printf("\n=== 测试完成 ===\n");
    return 0;
}
