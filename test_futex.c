// 测试 FUTEX 操作在 seccomp 沙箱中是否被允许
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

int test_futex_op(const char *name, int op, int expect_fail) {
    uint32_t val = 0;
    struct timespec timeout = {0, 0};
    
    long ret = syscall(SYS_futex, &val, op, 0, &timeout, NULL, 0);
    int actual_errno = errno;
    
    if (expect_fail) {
        if (ret == -1 && (actual_errno == EINVAL || actual_errno == EAGAIN || actual_errno == ESRCH || actual_errno == EDEADLK)) {
            printf("  ✓ %s: 返回 %ld (errno=%d) - 预期失败，操作被允许\n", name, ret, actual_errno);
            return 1;
        } else {
            printf("  ✗ %s: 返回 %ld (errno=%d) - 异常\n", name, ret, actual_errno);
            return 0;
        }
    } else {
        if (ret == -1 && actual_errno == ENOSYS) {
            printf("  ✗ %s: ENOSYS - 操作被 seccomp 阻止\n", name);
            return 0;
        } else if (ret == -1 && (actual_errno == EINVAL || actual_errno == EAGAIN || actual_errno == ESRCH || actual_errno == EDEADLK || actual_errno == ETIMEDOUT)) {
            printf("  ✓ %s: 返回 %ld (errno=%d) - 操作被允许\n", name, ret, actual_errno);
            return 1;
        } else {
            printf("  ? %s: 返回 %ld (errno=%d) - 不确定\n", name, ret, actual_errno);
            return -1;
        }
    }
}

int main() {
    printf("=== 测试 FUTEX 操作 ===\n");
    printf("当前进程: pid=%d, uid=%d\n\n", getpid(), getuid());
    
    // 测试基本 FUTEX 操作
    printf("1. 基本 FUTEX 操作:\n");
    test_futex_op("FUTEX_WAIT", FUTEX_WAIT, 1);
    test_futex_op("FUTEX_WAKE", FUTEX_WAKE, 1);
    
    // 测试 PI (Priority Inheritance) 操作
    printf("\n2. PI FUTEX 操作:\n");
    test_futex_op("FUTEX_LOCK_PI", FUTEX_LOCK_PI, 1);
    test_futex_op("FUTEX_UNLOCK_PI", FUTEX_UNLOCK_PI, 1);
    test_futex_op("FUTEX_TRYLOCK_PI", FUTEX_TRYLOCK_PI, 1);
    
    // 测试 REQUEUE PI 操作
    printf("\n3. REQUEUE PI 操作:\n");
    test_futex_op("FUTEX_WAIT_REQUEUE_PI", FUTEX_WAIT_REQUEUE_PI, 1);
    test_futex_op("FUTEX_CMP_REQUEUE_PI", FUTEX_CMP_REQUEUE_PI, 1);
    
    // 测试其他操作
    printf("\n4. 其他操作:\n");
    test_futex_op("FUTEX_FD", FUTEX_FD, 1);
    test_futex_op("FUTEX_REQUEUE", FUTEX_REQUEUE, 1);
    test_futex_op("FUTEX_CMP_REQUEUE", FUTEX_CMP_REQUEUE, 1);
    test_futex_op("FUTEX_WAKE_OP", FUTEX_WAKE_OP, 1);
    
    printf("\n=== 测试完成 ===\n");
    return 0;
}
