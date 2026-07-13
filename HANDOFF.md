# GhostLock OPPO Find N2 Exploit — Session Handoff

**Date**: 2026-07-14 (Updated)
**Device**: OPPO Find N2 (SM8475/CPH2413), Android 16, Kernel 5.10.236
**Project**: https://github.com/pubglite55/oppo-ghostlock/

---

## 1. Executive Summary

GhostLock (CVE-2026-43499) exploit chain targeting OPPO Find N2 is **stalled at slide pselect (栈覆盖)**:

- **KernelSnitch 已完全修复**: pile-up ✅, hashsize ✅, IDENTITY range ✅, bruteforce ✅
- **slide pselect 不可行**: waiter 在 fd_set 数据下方 120 字节，fd_set bitmaps 无法到达 waiter 位置
- **PR #11 merged**: boot_id 数据偏移修正
- **PR #12 merged**: P0_PAGE_OFFSET 和 P0_KERNEL_PHYS_LOAD 修正
- **PR #13 merged**: bypass slide，直接使用 direct-map kernel base

### Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| 偏移验证 | ✅ 完成 | vmlinux objdump + IDA 双重验证 |
| MM_STRUCT_SZ / MM_ORDER | ✅ 已确认 | 0x3c0 / 3 (pahole 验证) |
| futex_hashsize | ✅ 已修复 | 2048 (8 CPUs * 256) + roundup_pow_of_two |
| KernelSnitch pile-up 验证 | ✅ 已修复 | yield 16 次 + timing 测量 |
| KernelSnitch IDENTITY range | ✅ 已修复 | 0xffffff80-0xffffffc0 (direct-map) |
| KernelSnitch bruteforce | ✅ **成功** | mm_struct=0xffffff89807912c0 |
| KASLR bypass (slide) | ✅ 工作 | pselect side-channel 泄漏 nfulnl_logger |
| GhostLock FUTEX PI 触发 | ✅ 工作 | FUTEX_CMP_REQUEUE_PI ret=1 |
| sk_buff reclaim | ✅ 完成 | 4/4 send 成功 |
| **slide pselect (栈覆盖)** | ❌ **不可行** | waiter offset 120B — NFDS 扫描全部 DEAD |
| configfs R/W | ❌ **死路** | ashmem strcpy 行为 |
| pipe physrw | ⏳ 待实现 | 依赖栈覆盖修复 |
| root (cred + SELinux) | ⏳ 待实现 | 依赖 pipe physrw |

---

## 2. 关键技术细节

### 2.1 KernelSnitch 修复 (已验证)

**修复清单**:
1. IDENTITY range: `0xffffffc0-ffffffc4` → `0xffffff80-ffffffc0`
2. KSNITCH_COLLISIONS: 4 → 16
3. MM_STRUCT_SZ: 0x500 → 0x3c0
4. hashsize alignment: 添加 `roundup_pow2`
5. pile-up verification: yield 16 次 + timing 测量

**设备验证结果**:
```
[*] parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (16)
[*] pile-up verified: approx_time=2673
[*] found 15 collisisons
[*] leaked_mm=ffffff89807912c0 base=ffffff8980790000
[*] sk_buff reclaim send 4/4 ret=65536 errno=0
```

### 2.2 slide pselect 根因分析

**问题**: waiter 偏移错位 120 字节

**精确偏移计算 (IDA 验证)**:
```
pselect 帧链: pselect6(0xA0) + core_sys_select(0x1C0) + do_select(0x3C0) = 0x620
core_sys_select SP = stack_top - 0x260
fd_set 数据 (v35) = SP + 0x50 = stack_top - 0x210
waiter 结构 = stack_top - 0x288
偏移差 = 0x288 - 0x210 = 0x78 (120 bytes)
```

**`FRONTEND_STACK_ALLOC=256`** 确认阈值为 42.67 bytes，NFDS=320 是栈路径最大值。没有 NFDS 值能让 fd_set 覆盖 waiter 位置。

### 2.3 NFDS 扫描结果

| NFDS | v17 | 路径 | 结果 |
|------|-----|------|------|
| 320 | 40 | 栈缓冲区 | crash — waiter 在 fd_set 下方 120B |
| 321 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 344 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 640 | 80 | kvmalloc | crash — fd_set 不在栈上 |

### 2.4 PR #13 bypass slide

PR #13 移除了 slide leak 代码，直接使用 `P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD` 作为 kernel base。但 pselect 栈覆盖本身仍然不可行。

### 2.5 configfs type confusion (死路)

**问题**: ashmem SET_NAME 使用 strcpy 行为，内核地址 LE 首字节为 NUL → page 地址无法写入

**结论**: 无解决方案，此路径已放弃。

---

## 3. 下一步计划

### 优先级 1: 找到不依赖 pselect 栈覆盖的方法

当前 slide pselect 不可行。需要:
1. 分析 sendmsg 的栈布局 (`__sys_sendmsg` 帧大小 0x314)
2. 或寻找其他 syscall 将用户可控数据放置到 waiter 位置
3. 或重新设计 GhostLock trigger 机制

### 优先级 2: 完成 exploit 链

mm_struct 泄漏完成后:
1. pipe.c — pipe buffer 物理读写
2. fops.c — 伪造 fops, CFI bypass
3. root.c — 提权 (patch cred + SELinux)

---

## 4. 设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build fingerprint**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_NR_CPUS=32**, possible=0-7, online=8
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)
- **XBL firmware**: `0xa8000000` 内核物理加载地址

---

## 5. commit 历史

```
92b25d1 feat: skip slide, use direct-map kernel base for pipe physrw
b012fa3 feat: restore original CyberMeowfia PoC approach with shift=0
5949e63 docs: add PR #13 analysis report
f50448f fix: use P0_DATA_ALIAS_CONST for correct direct-map addresses
8693747 fix: restore correct SLIDE_ addresses for fake payload
94d111f fix: remove all slide references from fops.c and util.c
e316565 fix: add SLIDE_ defines and PSELECT_WAITER_WORD_SHIFT
f0d6a2a revert: restore PR #13 target.h exactly
69afa14 fix: add back SLIDE_ defines for compilation
6422b7a Merge pull request #13 (bypass slide)
a6792e7 docs: update AGENTS.md
addf8c4 docs: complete documentation system update
9a80fa4 Merge pull request #12 (slide crash fix)
dd6e708 fix slide crash
```
