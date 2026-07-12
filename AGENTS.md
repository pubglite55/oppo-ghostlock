# Agent Instructions

## What this repo is

Security research project exploiting GhostLock (CVE-2026-43499), a Linux kernel stack UAF via FUTEX_CMP_REQUEUE_PI race. Targets OPPO Find N2 (CPH2413, SM8475, kernel 5.10.236). The exploit chain: Firefox 151 CVE-2026-10702 → preload.so (LD_PRELOAD) → KernelSnitch (mm_struct leak) → GhostLock trigger → pipe physrw → root.

## Build

```bash
cd exploit/
make                    # 自动检测 NDK
make NDK=/path/to/ndk   # 指定 NDK 路径
```

Output: `preload.so` (128KB). Deploy via `adb push` + `LD_PRELOAD`.

## ⚠️ 关键适配要求 (Critical Adaptation Requirements)

### 1. 栈覆盖必须用户可控

**这是最关键的问题。** exploit 需要覆盖被释放的内核栈，且该栈必须在用户空间可控。

- Pixel 10 能成功是因为 pselect 的 `stack_fds` 正好和 `rt_waiter` 在内核栈上重合
- **简单适配偏移是不可能成功的！** 如果目标内核的栈布局不重合，或重合但不可控，必须找其他可控内核栈的系统调用

**已验证失败的方法 (OPPO Find N2):**

| 方法 | 结果 | 原因 |
|------|------|------|
| pselect (任意 NFDS) | fd_set 在堆上 | set_fd_set()→bitmap_alloc(), 用户数据不在栈上 |
| binder ioctl | EACCES | shell 用户无权限 |
| process_vm_readv | 帧仅 160B | 太浅 |
| PR_SET_MM_MAP | EPERM | Android 阻止 |
| poll | pollfd 在堆上 | kmalloc 分配, 用户数据不在栈上 |
| epoll_wait | 帧仅 0xE0 | 太浅 |

**下一个候选**: sendmsg — __sys_sendmsg 帧 0x314, 复制 cmsg 从用户到内核栈

**关键帧大小 (IDA output.elf 验证, 2026-07-12):**

| 函数 | 帧大小 |
|------|--------|
| __arm64_sys_futex | 0x90 (144B) |
| do_futex | 0x70 (112B) |
| futex_wait_requeue_pi | 0x1a0 (416B) |
| **总栈深** | **0x300 (768B)** |
| **waiter 距栈顶** | **0x288 (648B)** |

### 2. 结构体差异

- **5 系内核 vs 6 系内核**: `rt_mutex_waiter`、`task_struct` 等结构体布局不同
- **mm_struct 地址偏移**: 不同机型和内核版本必须用 pahole 精确提取
- **不能假设偏移相同** — 即使是同一主线版本，不同厂商的配置也可能不同

### 3. 适配难度评估

| 内核类型 | 适配难度 | 说明 |
|----------|----------|------|
| 同主线版本 | 低 | 改函数和结构偏移即可 |
| 同主线 + 相同配置 | 中 | 需要验证栈布局 |
| 非同主线版本 | **高** | 需要重新分析栈覆盖方法 |
| 厂商深度定制 | **极高** | 几乎需要重写 |

### 4. 建议的适配流程

1. **先完成栈覆盖验证**
   - 实现可控 panic，确认栈覆盖位置
   - 分析目标内核的系统调用栈布局
   - 找到用户可控数据能到达 waiter 位置的 syscall

2. **验证结构体偏移**
   - 从目标设备提取 vmlinux
   - 用 pahole 提取所有结构体偏移
   - 验证 mm_struct 地址泄漏

3. **测试 GhostLock 触发**
   - 确保 FUTEX_CMP_REQUEUE_PI 能正确触发
   - 验证悬空 pi_blocked_on 指针

4. **完成提权链**
   - pipe 物理读写
   - cred 结构体修补
   - SELinux 绕过

## Key gotchas

- **`TARGET_CONFIG_H` is mandatory** — `offset.h` errors without it. Pass as a `-D` string literal.
- **仓库帧大小全部错误** — HANDOFF.md 旧值 (sys_futex=0x70, do_futex=0x130, do_select=0x390) 均不正确。IDA 验证: sys_futex=0x90, do_futex=0x70, do_select=0x3C0。必须使用 IDA output.elf 数据。
- **KASLR bypass (slide) 阻塞** — Waiter 在 `stack_top - 0x288` (648B), 无 syscall 能在此偏移写入用户可控数据。这是主要阻塞点。
- **pselect fd_set 在堆上** — set_fd_set()→bitmap_alloc(), 用户数据不在内核栈上。pselect 无法用于 stack reclaim。
- **Firefox 151 required** — CVE-2026-10702 only exists in version 151.0.

## Architecture notes

- **No CI, no linter, no tests** — pure research repo
- **Target-specific offsets** live in `exploit/targets/oppo-find_n2/target.h` (201 lines of #defines, all pahole-verified)
- **KernelSnitch** uses futex hash collisions + ashmem to leak mm_struct
- **Analysis scripts** in `analysis-scripts/` — kernel call chain analysis
- **Test programs** in `test-programs/` — standalone tests for futex, binder, pselect, reclaim, seccomp

## Project status

| Stage | Status |
|-------|--------|
| KernelSnitch mm_struct leak | Working |
| SKB payload preparation | Working |
| GhostLock FUTEX PI trigger | Fails (ETIMEDOUT, wrong sync) |
| KASLR bypass (slide) | **Blocked** (no syscall reaches waiter position) |
| pipe physrw | Pending (depends on KASLR) |
| root (cred + SELinux) | Pending (depends on KASLR) |

## Reference docs

- `HANDOFF.md` — detailed session handoff with all technical findings
- `docs/architecture.md` — exploit chain architecture diagram
- `docs/knowledge-notes.md` — SLUB order calc, rt_mutex_waiter layout, boot image format
- `TROUBLESHOOTING.md` — build errors, runtime failures, environment issues
- NebuSec writeup: https://nebusec.ai/research/ionstack-part-2/
- CyberMeowfia PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c
