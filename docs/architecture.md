# GhostLock 架构设计

## 设计理念

本项目基于 NebuSec CyberMeowfia 的 GhostLock exploit chain，针对 OPPO Find N2 (SM8475, kernel 5.10.236) 进行适配。核心设计原则：

1. **IDA 验证优先** — 所有内核偏移必须通过 IDA output.elf 验证，不信任仓库默认值
2. **独立可测试** — 每个阶段可单独编译测试
3. **设备验证驱动** — 所有修复必须在真实设备上验证

## 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Exploit Chain (6 stages)                  │
├─────────────────────────────────────────────────────────────┤
│ Stage 1: Firefox CVE-2026-10702                             │
│   SpiderMonkey type confusion → fake TypedArray → AAW       │
├─────────────────────────────────────────────────────────────┤
│ Stage 2: KASLR bypass (slide/pselect)                       │
│   pselect side-channel → leak nfulnl_logger → kernel base   │
├─────────────────────────────────────────────────────────────┤
│ Stage 3: mm_struct leak (KernelSnitch)                      │
│   futex hash timing → bruteforce direct-map → mm_struct     │
├─────────────────────────────────────────────────────────────┤
│ Stage 3.5: sk_buff reclaim                                  │
│   fake payload → reclaim kernel page                        │
├─────────────────────────────────────────────────────────────┤
│ Stage 3.5: slide pselect (栈覆盖) ← ❌ 当前阻塞            │
│   waiter offset mismatch → kernel panic                     │
├─────────────────────────────────────────────────────────────┤
│ Stage 4: configfs R/W ← ❌ DEAD (ashmem strcpy)            │
├─────────────────────────────────────────────────────────────┤
│ Stage 5: pipe physrw → Stage 6: root                        │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块详解

### 1. KernelSnitch (futex hash timing)

**功能**: 通过 futex hash 碰撞检测泄漏内核 mm_struct 地址

**输入**: 4096 个线程在 futex bucket 128 上堆积 (pile-up)
**输出**: mm_struct 内核地址

**关键实现**:
- `kernelsnitch.h` — pile-up 创建 + 碰撞检测 + bruteforce
- `futex_hash.h` — Jenkins jhash2, futex_key_t union, futex_init()
- `timeutils.h` — ARM `mrs cntvct_el0` with ISB barriers

**流程**:
1. `__increase(ks, ID=128, 4096)` — 4096 线程 `FUTEX_WAIT_PRIVATE` on bucket 128
2. `kernelsnitch_find_collisions()` — 扫描其他 futex 地址, 测量 `FUTEX_WAKE_PRIVATE` timing
3. `kernelsnitch_bruteforce()` — 测试每个 mm_struct 候选, 用 `futex_hash(addr, candidate_mm)` 验证

**已修复的 bug**:
- pile-up verification: 添加 atomic counter + timing 验证
- hashsize alignment: `roundup_pow2(nr_cpu_ids * 256)` 匹配内核
- IDENTITY range: `0xffffff80-0xffffffc0` (direct-map, 非 kernel image)
- KSNITCH_COLLISIONS: 4 → 16
- MM_STRUCT_SZ: 0x500 → 0x3c0

### 2. KASLR bypass (slide/pselect)

**功能**: 利用 pselect side-channel 泄漏内核地址，推导 kernel base

**输入**: fd_set bitmaps with fake waiter words
**输出**: kernel base address

**关键符号**:
- `SLIDE_NFULNL_LOGGER_OFF=0x027c14b8` — 泄漏目标
- `SLIDE_RANDOM_BOOT_ID_DATA_OFF=0x02b99b6d` — boot_id 数据

### 3. GhostLock FUTEX PI trigger

**功能**: 通过 FUTEX_CMP_REQUEUE_PI 触发 rtmutex PI chain walk

**触发条件**:
- 3 futex words + 3 threads → PI 依赖循环 → -EDEADLK → 错误回滚
- `remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`

### 4. slide pselect (栈覆盖) ← 当前阻塞

**问题**: waiter 偏移错位 120 字节

**精确偏移计算 (IDA 验证)**:
```
pselect 帧链: pselect6(0xA0) + core_sys_select(0x1C0) + do_select(0x3C0) = 0x620
core_sys_select SP = stack_top - 0x260
fd_set 数据 (v35) = SP + 0x50 = stack_top - 0x210
waiter 结构 = stack_top - 0x288
偏移差 = 0x288 - 0x210 = 0x78 (120 bytes)
```

**根因**: waiter 在 fd_set 数据**下方** 120 字节。fd_set bitmaps 从 stack_top - 0x210 开始向**上**增长，无法覆盖到 stack_top - 0x288 的 waiter 位置。

**`FRONTEND_STACK_ALLOC=256`** 确认阈值为 42.67 bytes，NFDS=320 是栈路径最大值。没有 NFDS 值能让 fd_set 覆盖 waiter 位置。

## 技术选型说明

### KernelSnitch vs pselect side-channel

| 方法 | 泄漏数据 | 可用性 |
|------|----------|--------|
| pselect side-channel | 内核栈数据 (nfulnl_logger) | ✅ 用于 KASLR bypass |
| KernelSnitch | slab 数据 (mm_struct) | ✅ 用于 mm_struct 泄漏 |

**选择 KernelSnitch 的原因**: mm_struct 在 slab 分配器中，不在内核栈上，pselect 无法直接泄漏。

### NFDS 选择

| NFDS | v17 | 路径 | fd_set 位置 |
|------|-----|------|-------------|
| 320 | 40 | 栈缓冲区 (v35) | 内核栈 SP+0x50 |
| 344 | 48 | kvmalloc | 堆 |

**结论**: NFDS=344 走堆路径，fd_set 数据不在栈上，fake waiter 数据无法通过 fd_set 写入内核栈。

### PR #13 bypass slide

PR #13 移除了 slide leak 代码，直接使用 `P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD` 作为 kernel base。但 pselect 栈覆盖本身仍然不可行。

### NFDS 扫描结果

| NFDS | v17 | 路径 | 结果 |
|------|-----|------|------|
| 320 | 40 | 栈缓冲区 | crash — waiter 在 fd_set 下方 120B |
| 321 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 344 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 640 | 80 | kvmalloc | crash — fd_set 不在栈上 |

**结论**: 没有 NFDS 值能让 fd_set 覆盖 waiter 位置。需要完全重新设计 slide 机制。
