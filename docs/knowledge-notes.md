# 技术知识沉淀

## 核心技术点深度笔记

### 1. SLUB 分配器 slab order 计算

SLUB 分配器根据对象大小自动选择 slab order：

```python
# SLUB slab order 计算逻辑
mm_struct_size = 960  # mm_struct + cpumask
nr_cpu_ids = 8
page_size = 4096

# min_objects = 4 * (fls(nr_cpu_ids) + 1)
fls_val = 4  # fls(8) = 4
min_objects = 4 * (4 + 1) = 20

# 对于 mm_struct (960 bytes):
# order=0: 4096/960 = 4 objects < 20
# order=1: 8192/960 = 8 objects < 20
# order=2: 16384/960 = 17 objects < 20
# order=3: 32768/960 = 34 objects >= 20  ← 选择这个

MM_ORDER = 3
slab_size = 32768  # 32KB
objects_per_slab = 34
```

### 2. Android Boot Image 格式

```
+-------------------+
| Boot Header       | (1 page = 2048 bytes)
+-------------------+
| Kernel (PE/COFF)  | (VA: 0x10000)
|   .text section   | (39MB)
|   .data section   | (2.3MB)
+-------------------+
| Ramdisk           |
+-------------------+
```

### 3. FUTEX PI 操作在 seccomp 中的限制

Firefox 的 seccomp 沙箱 (Seccomp=2, filters=1) 可能阻止:
- `FUTEX_LOCK_PI` - PI 优先级继承锁
- `FUTEX_WAIT_REQUEUE_PI` - 带重排队的等待
- `FUTEX_CMP_REQUEUE_PI` - 带比较的重排队

但基本 FUTEX 操作 (FUTEX_WAIT, FUTEX_WAKE) 通常被允许。

### 4. rt_mutex_waiter 结构体布局

```c
struct rt_mutex_waiter {                    // pahole 验证
    struct rb_node tree_entry;             // 0x00 (24 bytes)
    struct rb_node pi_tree_entry;          // 0x18 (24 bytes)
    struct task_struct *task;              // 0x30 (8 bytes)
    struct rt_mutex *lock;                 // 0x38 (8 bytes)
    int prio;                              // 0x40 (4 bytes)
    // 4 bytes padding
    u64 deadline;                          // 0x48 (8 bytes)
};                                         // 总大小: 80 bytes
```

## 开发思路与方案对比记录

### 偏移提取方案对比

| 方案 | 优点 | 缺点 | 结果 |
|------|------|------|------|
| 手动计算 | 简单 | 不准确 | ❌ 失败 |
| pahole (编译内核) | 精确 | 需要 Linux 服务器 | ✅ 成功 |
| pyelftools | 跨平台 | 需要 DWARF 信息 | ⚠️ 部分成功 |

### KASLR 绕过方案对比

| 方案 | 技术 | 兼容性 | 结果 |
|------|------|--------|------|
| Prefetch | 时序侧信道 | 需要 KPTI 关闭 | ❌ |
| Slide/pselect | pselect 时序 | 通用 | ✅ |
| EntryBleed | 通过 trampoline | 需要特定条件 | ❌ |

### mm_struct 泄漏方案对比

| 方案 | 原理 | 复杂度 | 结果 |
|------|------|--------|------|
| KernelSnitch | futex 哈希时序 | 中等 | ✅ |
| PR_SET_MM_MAP | prctl 栈回收 | 高 | ❌ 未尝试 |
| /proc/self/pagemap | 物理页映射 | 低 | ❌ 被阻止 |

## 可复用的代码片段

### pahole 偏移提取命令

```bash
# 从 vmlinux 提取结构体偏移
pahole -C task_struct vmlinux > task_offsets.txt
pahole -C cred vmlinux > cred_offsets.txt
pahole -C rt_mutex_waiter vmlinux > waiter_offsets.txt
pahole -C file_operations vmlinux > fops_offsets.txt

# 从 vmlinux 提取符号地址
aarch64-linux-gnu-nm vmlinux | grep -E \
  "init_task$|root_task_group$|ashmem_ioctl$|noop_llseek$" > symbols.txt
```

### SLUB slab order 计算

```python
def calculate_slub_order(object_size, nr_cpu_ids=8, page_size=4096):
    """计算 SLUB slab order"""
    fls_val = nr_cpu_ids.bit_length()
    min_objects = 4 * (fls_val + 1)
    
    for order in range(4):
        slab_size = page_size * (1 << order)
        objects = slab_size // object_size
        if objects >= min_objects:
            return order, slab_size, objects
    
    return 3, page_size * 8, (page_size * 8) // object_size
```

### FUTEX 操作测试

```c
// 测试 FUTEX PI 操作是否被 seccomp 阻止
uint32_t val = 0;
long ret;

ret = syscall(SYS_futex, &val, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
printf("FUTEX_LOCK_PI: ret=%ld errno=%d\n", ret, errno);

ret = syscall(SYS_futex, &val, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
printf("FUTEX_UNLOCK_PI: ret=%ld errno=%d\n", ret, errno);
```

## 非常规操作的原理说明

### 为什么 KernelSnitch 使用 ashmem 而不是 mmap

Firefox 的 seccomp 沙箱可能阻止大规模 mmap (64GB)，但 ashmem 是 Android 特有的共享内存机制，可能绕过这些限制。

### 为什么需要 Firefox 151

CVE-2026-10702 漏洞存在于 Firefox 151.0 中。Firefox 152 已修复此漏洞，因此必须使用 151 版本。

### 为什么 OPPO 设备需要特殊处理

OPPO 的内核配置与 Pixel 不同：
1. 缺失 vendor/o 目录
2. 需要特殊的 Kconfig 文件
3. seccomp 沙箱更严格
4. 内核结构体布局可能有差异
