# Agent Instructions

## What this repo is

Security research project exploiting GhostLock (CVE-2026-43499), a Linux kernel stack UAF via FUTEX_CMP_REQUEUE_PI race. Targets OPPO Find N2 (CPH2413, SM8475, kernel 5.10.236). The exploit chain: Firefox 151 CVE-2026-10702 → preload.so (LD_PRELOAD) → KernelSnitch (mm_struct leak) → GhostLock trigger → pipe physrw → root.

## Build

```bash
cd exploit/
make NDK=/tmp/ndk_extract/android-ndk-r29   # REQUIRED: android35 has shadow stack OOM
```

Output: `preload.so` (128KB). Deploy via `adb push` + `LD_PRELOAD`.

## Deploy & Test

```bash
adb push preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## Current Blockers (2026-07-14)

### BLOCKER 1: slide pselect (栈覆盖) — 不可行

**根因**: waiter 在 fd_set 数据下方 120 字节，fd_set bitmaps 无法到达 waiter 位置。

```
fd_set 数据: stack_top - 0x210 (core_sys_select SP+0x50)
waiter: stack_top - 0x288 (do_select 帧内)
偏移差: 0x78 (120 bytes)
```

`FRONTEND_STACK_ALLOC=256` 确认阈值为 42.67 bytes，NFDS=320 是栈路径最大值。没有 NFDS 值能让 fd_set 覆盖 waiter 位置。

**NFDS 扫描结果 (全部失败)**:

| NFDS | v17 | 路径 | 结果 |
|------|-----|------|------|
| 320 | 40 | 栈缓冲区 | crash — waiter 在 fd_set 下方 120B |
| 321 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 344 | 48 | kvmalloc | crash — fd_set 不在栈上 |
| 640 | 80 | kvmalloc | crash — fd_set 不在栈上 |

### BLOCKER 2: configfs type confusion — DEAD

ashmem SET_NAME 使用 strcpy 行为，内核地址 LE 首字节为 NUL → page 地址无法写入。

## Key Gotchas

- **`TARGET_CONFIG_H` is mandatory** — offset.h errors without it. Pass as `-D` string literal.
- **Frame sizes in repo are WRONG** — must use IDA-verified values (see table below)
- **NDK must be r29 with `aarch64-linux-android35-clang`** — android35 causes shadow stack OOM
- **device has no root** — cannot use strace, kallsyms, dmesg
- **Firefox 151 required** — CVE-2026-10702 only exists in version 51.0
- **KernelSnitch timing works on kernel 5.10** — futex_wake identical across 5.10/5.15/6.1/6.12
- **PR #11 merged**: boot_id data offset `0x02b99acd` → `0x02b99b6d`
- **PR #12 merged**: P0_PAGE_OFFSET `0xffffffc000000000` → `0xffffff8000000000`, P0_KERNEL_PHYS_LOAD `0x80000000` → `0xa8000000`

## Verified Frame Sizes (IDA output.elf)

| Function | Frame | Notes |
|----------|-------|-------|
| `__arm64_sys_futex` | 0x90 | SUB SP,SP,#0x90 |
| `do_futex` | 0x70 | SUB SP,SP,#0x70 |
| `futex_wait_requeue_pi` | 0x1A0 | SUB SP,SP,#0x1A0 |
| **Total futex chain** | **0x300** | 768B |
| **waiter offset from stack top** | **0x288** | 648B |
| `__arm64_sys_pselect6` | 0xA0 | SUB SP,SP,#0xA0 |
| `core_sys_select` | 0x1C0 | SUB SP,SP,#0x1C0 |
| `do_select` | 0x3C0 | STP+0x60 + SUB+0x360 |

**WARNING**: Previous repo values were wrong (sys_futex=0x70, do_futex=0x130, do_select=0x390). Always use IDA values.

## Dead Ends (Do Not Repeat)

| Method | Why it failed |
|--------|---------------|
| NFDS=320 | waiter 在 fd_set 下方 120B，无法覆盖 |
| NFDS=321-640 | 走 kvmalloc 路径，fd_set 不在栈上 |
| pselect fd_set on stack | set_fd_set()→bitmap_alloc(), fd_set on heap not stack |
| configfs type confusion | ashmem strcpy, kernel addr LE first byte is NUL |
| pselect for mm_struct | leaks kernel stack data, not slab data |
| Pipe reclaim without mm_struct | all functions depend on KernelSnitch |
| binder ioctl | EACCES (shell user) |
| PR_SET_MM_MAP | EPERM (Android blocks) |
| perf_event_open | SELinux denies |
| /proc/kallsyms | kptr_restrict enforced |

## Architecture

- **No CI, no linter, no tests** — pure research repo
- **Target offsets**: `exploit/targets/oppo-find_n2/target.h` (pahole + IDA verified)
- **KernelSnitch**: futex hash collisions + ashmem to leak mm_struct
- **Analysis scripts**: `analysis-scripts/`
- **Test programs**: `test-programs/`

## Project Status

| Stage | Status | Notes |
|-------|--------|-------|
| Firefox CVE-2026-10702 | ✅ Working | |
| KASLR bypass (slide) | ✅ Working | pselect side-channel leaks nfulnl_logger |
| GhostLock FUTEX PI trigger | ✅ Working | FUTEX_CMP_REQUEUE_PI ret=1 |
| KernelSnitch mm_struct leak | ✅ **Working** | bruteforce found mm_struct |
| sk_buff reclaim | ✅ Working | 4/4 send success |
| slide pselect crash | ❌ **NOT VIABLE** | waiter offset 120 bytes — NFDS sweep confirmed no solution |
| configfs R/W | ❌ **DEAD** | ashmem strcpy behavior |
| pipe physrw | ⏳ Pending | depends on stack cover fix |
| root (cred + SELinux) | ⏳ Pending | depends on pipe physrw |

## Reference Docs

- `HANDOFF.md` — detailed session handoff
- `docs/architecture.md` — exploit chain diagram
- `docs/knowledge-notes.md` — SLUB order, rt_mutex_waiter layout
- NebuSec writeup: https://nebusec.ai/research/ionstack-part-2/
- CyberMeowfia PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c
