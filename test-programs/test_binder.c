#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#define BINDER_WRITE_READ _IOW('r', 0, char[48])
#define BINDER_SET_CONTEXT_MGR _IO('r', 7)
#define BINDER_VERSION _IOW('r', 9, int[2])

int main() {
    int fd = open("/dev/binder", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 1; }
    printf("[*] binder fd=%d\n", fd);

    /* Try BINDER_VERSION first */
    int ver[2] = {-1, -1};
    int ret = ioctl(fd, BINDER_VERSION, ver);
    printf("[*] BINDER_VERSION: ret=%d errno=%d ver=%d\n", ret, errno, ver[0]);

    /* Try empty BINDER_WRITE_READ */
    unsigned long bwr[8];
    memset(bwr, 0, sizeof(bwr));
    ret = ioctl(fd, BINDER_WRITE_READ, bwr);
    printf("[*] BINDER_WRITE_READ (empty): ret=%d errno=%d\n", ret, errno);

    /* Try with write_size=8 */
    unsigned long dummy = 0;
    bwr[0] = 8;  /* write_size */
    bwr[1] = 0;  /* write_consumed */
    bwr[2] = (unsigned long)&dummy;  /* write_buffer */
    bwr[3] = 0;  /* read_size */
    bwr[4] = 0;  /* read_consumed */
    bwr[5] = 0;  /* read_buffer */
    ret = ioctl(fd, BINDER_WRITE_READ, bwr);
    printf("[*] BINDER_WRITE_READ (write=8): ret=%d errno=%d\n", ret, errno);

    close(fd);
    return 0;
}
