// 在 Firefox seccomp 沙箱内测试 FUTEX PI 操作
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

// 从 /proc/self/status 读取 seccomp 状态
int get_seccomp_info(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int mode = -1, filters = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            mode = atoi(line + 8);
        } else if (strncmp(line, "Seccomp_filters:", 16) == 0) {
            filters = atoi(line + 16);
        }
    }
    fclose(f);
    printf("[*] Seccomp: mode=%d filters=%d\n", mode, filters);
    return mode;
}

// 测试 FUTEX PI 操作
int test_futex_pi(void) {
    printf("\n=== 测试 FUTEX PI 操作 ===\n");
    
    // 创建一个共享内存用于 futex
    uint32_t *futex_addr = mmap(NULL, sizeof(uint32_t), 
                                 PROT_READ | PROT_WRITE, 
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (futex_addr == MAP_FAILED) {
        printf("[-] mmap 失败: %m\n");
        return -1;
    }
    *futex_addr = 0;
    
    uint32_t *futex_addr2 = mmap(NULL, sizeof(uint32_t), 
                                  PROT_READ | PROT_WRITE, 
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (futex_addr2 == MAP_FAILED) {
        printf("[-] mmap 第二个 futex 失败: %m\n");
        munmap(futex_addr, sizeof(uint32_t));
        return -1;
    }
    *futex_addr2 = 0;
    
    long ret;
    
    // 测试 FUTEX_LOCK_PI
    printf("[*] 测试 FUTEX_LOCK_PI... ");
    ret = syscall(SYS_futex, futex_addr, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("ret=%ld errno=%d (%s)\n", ret, errno, 
           ret == 0 ? "成功" : strerror(errno));
    int lock_pi_ok = (ret == 0);
    
    // 测试 FUTEX_TRYLOCK_PI
    printf("[*] 测试 FUTEX_TRYLOCK_PI... ");
    ret = syscall(SYS_futex, futex_addr, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    printf("ret=%ld errno=%d (%s)\n", ret, errno,
           ret == 0 ? "成功" : (ret == -1 && errno == EBUSY ? "EBUSY(已锁定)" : strerror(errno)));
    
    // 测试 FUTEX_UNLOCK_PI
    printf("[*] 测试 FUTEX_UNLOCK_PI... ");
    ret = syscall(SYS_futex, futex_addr, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("ret=%ld errno=%d (%s)\n", ret, errno,
           ret == 0 ? "成功" : strerror(errno));
    
    // 测试 FUTEX_WAIT_REQUEUE_PI
    printf("[*] 测试 FUTEX_WAIT_REQUEUE_PI... ");
    struct timespec timeout = {0, 1000000}; // 1ms timeout
    ret = syscall(SYS_futex, futex_addr, FUTEX_WAIT_REQUEUE_PI, 0, 
                  &timeout, futex_addr2, 0);
    printf("ret=%ld errno=%d (%s)\n", ret, errno,
           (ret == -1 && errno == ETIMEDOUT) ? "ETIMEDOUT(预期)" : strerror(errno));
    
    // 测试 FUTEX_CMP_REQUEUE_PI (关键!)
    printf("[*] 测试 FUTEX_CMP_REQUEUE_PI... ");
    ret = syscall(SYS_futex, futex_addr, FUTEX_CMP_REQUEUE_PI, 1, 
                  (void*)1, futex_addr2, 0);
    printf("ret=%ld errno=%d (%s)\n", ret, errno,
           (ret == -1 && (errno == EINVAL || errno == ESRCH)) ? "OK(参数错误但系统调用允许)" : strerror(errno));
    
    // 清理
    munmap(futex_addr, sizeof(uint32_t));
    munmap(futex_addr2, sizeof(uint32_t));
    
    printf("=== FUTEX PI 测试完成 ===\n");
    return 0;
}

int main(int argc, char **argv) {
    printf("[*] FUTEX PI 测试程序 (在 seccomp 沙箱内)\n");
    printf("[*] PID: %d, UID: %d\n", getpid(), getuid());
    
    get_seccomp_info();
    test_futex_pi();
    
    return 0;
}
