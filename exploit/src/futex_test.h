// FUTEX 操作测试 - 在 Firefox 沙箱内运行
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <unistd.h>

static int test_futex_in_sandbox(void) {
    uint32_t val = 0;
    long ret;
    int blocked = 0;
    
    printf("[*] 测试 FUTEX 操作 (seccomp=%d, filters=%d)\n", 
           get_seccomp_mode(), get_seccomp_filters());
    
    // 测试 FUTEX_WAIT
    ret = syscall(SYS_futex, &val, FUTEX_WAIT, 0, NULL, NULL, 0);
    printf("  FUTEX_WAIT: ret=%ld errno=%d %s\n", ret, errno, 
           (ret == -1 && errno == EAGAIN) ? "OK" : "BLOCKED?");
    
    // 测试 FUTEX_WAKE
    val = 1;
    ret = syscall(SYS_futex, &val, FUTEX_WAKE, 1, NULL, NULL, 0);
    printf("  FUTEX_WAKE: ret=%ld errno=%d %s\n", ret, errno,
           (ret >= 0) ? "OK" : "BLOCKED?");
    
    // 测试 FUTEX_LOCK_PI
    val = 0;
    ret = syscall(SYS_futex, &val, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("  FUTEX_LOCK_PI: ret=%ld errno=%d %s\n", ret, errno,
           (ret == 0) ? "OK" : "BLOCKED?");
    
    // 测试 FUTEX_CMP_REQUEUE_PI
    uint32_t val2 = 0;
    ret = syscall(SYS_futex, &val, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &val2, 0);
    printf("  FUTEX_CMP_REQUEUE_PI: ret=%ld errno=%d %s\n", ret, errno,
           (ret == -1 && errno == EINVAL) ? "OK (EINVAL expected)" : "BLOCKED?");
    
    return 0;
}

static int get_seccomp_mode(void) {
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            int mode = atoi(line + 8);
            fclose(f);
            return mode;
        }
    }
    fclose(f);
    return -1;
}

static int get_seccomp_filters(void) {
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp_filters:", 16) == 0) {
            int filters = atoi(line + 16);
            fclose(f);
            return filters;
        }
    }
    fclose(f);
    return -1;
}
