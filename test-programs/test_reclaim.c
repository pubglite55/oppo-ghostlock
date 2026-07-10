#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <linux/keyctl.h>
#include <sys/resource.h>

#define SYS_pselect6 72
#define SYS_process_vm_readv 271
#define SYS_process_vm_writev 272
#define SYS_keyctl 250
#define SYS_timerfd_create 530
#define SYS_fcntl 1030

int main() {
    char buf[512];
    memset(buf, 0x41, sizeof(buf));
    int ret, saved_errno;

    /* 1. pselect6 */
    {
        struct timespec ts = {0, 0};
        ret = syscall(SYS_pselect6, 256, buf, buf, buf, &ts, 0);
        saved_errno = errno;
        printf("[*] pselect6(256): ret=%d errno=%d %s\n", ret, saved_errno,
               saved_errno == 0 ? "OK" : strerror(saved_errno));
    }

    /* 2. process_vm_readv */
    {
        struct iovec iov = {buf, 8};
        ret = syscall(SYS_process_vm_readv, getpid(), &iov, 1, &iov, 1, 0);
        saved_errno = errno;
        printf("[*] process_vm_readv: ret=%d errno=%d %s\n", ret, saved_errno,
               ret >= 0 ? "OK" : strerror(saved_errno));
    }

    /* 3. getsockopt TCP_ZEROCOPY_RECEIVE */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        socklen_t len = 128;
        char optval[128] = {0};
        ret = syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, optval, &len);
        saved_errno = errno;
        printf("[*] getsockopt(TCP_ZEROCOPY): ret=%d errno=%d %s\n", ret, saved_errno,
               ret == 0 ? "OK" : strerror(saved_errno));
        close(fd);
    }

    /* 4. setpriority (for PI chain walk test) */
    {
        ret = setpriority(PRIO_PROCESS, getpid(), 0);
        saved_errno = errno;
        printf("[*] setpriority: ret=%d errno=%d %s\n", ret, saved_errno,
               ret == 0 ? "OK" : strerror(saved_errno));
    }

    /* 5. timerfd_create + fcntl F_DUPFD */
    {
        int fd = syscall(SYS_timerfd_create, 1 /*CLOCK_MONOTONIC*/, 0);
        saved_errno = errno;
        printf("[*] timerfd_create: fd=%d errno=%d %s\n", fd, saved_errno,
               fd >= 0 ? "OK" : strerror(saved_errno));
        if (fd >= 0) {
            int dup_fd = syscall(SYS_fcntl, fd, 1030 /*F_DUPFD*/, 32);
            saved_errno = errno;
            printf("[*] fcntl(F_DUPFD,32): ret=%d errno=%d %s\n", dup_fd, saved_errno,
                   dup_fd >= 0 ? "OK" : strerror(saved_errno));
            close(fd);
            if (dup_fd >= 0) close(dup_fd);
        }
    }

    return 0;
}
