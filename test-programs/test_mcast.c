#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    /* MCAST_JOIN_SOURCE_GROUP = 46 on IPv6 */
    struct group_source_req {
        struct group_filter gsf;
    };
    struct group_source_req gsr;
    memset(&gsr, 0, sizeof(gsr));
    gsr.gsf.gf_interface = 0;
    gsr.gsf.gf_group.ss_family = AF_INET6;

    int ret = setsockopt(fd, IPPROTO_IPV6, 46, &gsr, sizeof(gsr));
    printf("[*] MCAST_JOIN_SOURCE_GROUP: ret=%d errno=%d %s\n",
           ret, errno, ret == 0 ? "OK" : strerror(errno));

    /* Also try MCAST_LEAVE_SOURCE_GROUP */
    ret = setsockopt(fd, IPPROTO_IPV6, 47, &gsr, sizeof(gsr));
    printf("[*] MCAST_LEAVE_SOURCE_GROUP: ret=%d errno=%d %s\n",
           ret, errno, ret == 0 ? "OK" : strerror(errno));

    close(fd);
    return 0;
}
