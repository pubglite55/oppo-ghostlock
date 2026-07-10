# GhostLock OPPO Find N2 Exploit — Session Handoff

**Date**: 2026-07-11  
**Device**: OPPO Find N2 (SM8475/CPH2413), Android 16, Kernel 5.10.236  
**Project**: https://github.com/pubglite55/oppo-ghostlock/

---

## 1. Executive Summary

GhostLock (CVE-2026-43499) exploit chain targeting OPPO Find N2 is **stalled at KASLR bypass (slide mechanism)**. The blocker is finding a syscall that writes user-controlled data at the correct kernel stack position to overlap with the forged waiter.

### What Works
| Component | Status | Notes |
|-----------|--------|-------|
| IDA Pro 9.3 + MCP | ✅ Installed | macOS x64, patched, MCP configured |
| KernelSnitch mm_struct leak | ✅ Working | Fixed futex_hashsize (use _SC_NPROCESSORS_CONF) |
| SKB payload preparation | ✅ Working | order-3 slab, 32KB pages |
| GhostLock FUTEX PI trigger | ✅ Working | 3 futex words, 3 threads, -EDEADLK |
| KASLR bypass (slide) | ❌ BLOCKED | **No syscall writes user data at waiter position** |

### What Failed (Stack Reclaim Methods)
| Method | Result | Root Cause |
|--------|--------|------------|
| pselect (NFDS=384) | EBADF, no overlap | fd_set at stack_top-0x1f8, waiter at stack_top-0x358 (352B gap) |
| pselect (NFDS=1024) | EBADF, no overlap | fd_set on heap (kvmalloc), not on stack |
| binder ioctl | EACCES (errno=13) | Shell user has no permission to /dev/binder |
| process_vm_readv | OK but no overlap | Frame only 160B, too shallow |
| PR_SET_MM_MAP | EPERM | Android blocks this |
| setsockopt MCAST | EADDRNOTAVAIL | IPv6 multicast restricted |
| keyctl | EOPNOTSUPP | Not supported |
| timerfd_create | ENOSYS | Blocked by seccomp |
| prefetch side-channel | All 0 cycles | KPTI enabled (CONFIG_UNMAP_KERNEL_AT_EL0=y) |
| /proc/kallsyms | Permission denied | kptr_restrict enforced |

---

## 2. CRITICAL: Waiter Position Analysis (boot-2.img Verified)

### Frame Sizes (from boot-2.img extracted kernel, NOT server vmlinux)

| Function | Frame Size | Source |
|----------|-----------|--------|
| sys_futex | 0x10 (16B) | STP X29,X30,[SP,#-0x10]! |
| do_futex | 0x1c0 (448B) | SUB SP,SP,#0x1c0 |
| futex_wait_requeue_pi | 0x1a0 (416B) | SUB SP,SP,#0x1a0 |
| **Total futex chain** | **0x3d0 (976B)** | |
| **Waiter距栈顶** | **0x358 (856B)** | 0x3d0 - 0x78 |

### ⚠️ IMPORTANT: Server vmlinux frame sizes are WRONG
- Server do_futex: 0x130 (304B) vs boot-2.img: **0x1c0 (448B)** — 144B difference!
- Server sys_futex: 0x70 (112B) vs boot-2.img: **0x10 (16B)** — 96B difference!
- **ALL frame size analysis must use boot-2.img extracted kernel**

### pselect Chain Analysis
| Function | Frame Size |
|----------|-----------|
| sys_pselect6 | 0x90 (144B) |
| core_sys_select | 0x1d0 (464B) |
| do_select | 0x390 (912B) — STP 0x60 + SUB 0x330 |
| **Total** | **0x610 (1552B)** |

- fd_set data位置: stack_top - 0x1f8 (504B) — 在 core_sys_select 帧内 SP+0x68
- waiter位置: stack_top - 0x358 (856B) — 在 do_select 帧内
- **差距: 352B — fd_set 无法触及 waiter**
- do_select 在 waiter 位置 (SP+0x298) 没有任何数据写入

### Key Constraint
**The issue is NOT just total chain depth — it's WHERE user-controlled data lands.** Even with deep chain (pselect=1552B), if user data is at wrong offset (0x1f8 vs 0x358), it doesn't help. Need a syscall where user-controlled data is placed at stack_top - 0x358 specifically.

---

## 3. Files & Locations

### Local Machine (macOS)
```
/Users/xiuxiu391/Desktop/oppo/
├── boot-2.img              — Original boot image (192MB) ★ AUTHORITATIVE SOURCE
├── vmlinux.elf             — Extracted kernel ELF (46MB, .text at 0x0)
├── vmlinux.gz              — Compressed kernel
├── extract-vmlinux         — Kernel extraction script
├── exploit/
│   ├── src/
│   │   ├── main.c          — Entry point, seccomp/FUTEX PI test
│   │   ├── util.c          — KernelSnitch setup, SKB payload, configfs R/W
│   │   ├── slide.c         — KASLR bypass (currently process_vm_readv, needs update)
│   │   ├── fops.c          — Fake fops, CFI stage
│   │   ├── pipe.c          — Pipe buffer physical R/W
│   │   ├── root.c          — Privilege escalation
│   │   ├── preload.c       — LD_PRELOAD entry
│   │   ├── common.h        — MM_STRUCT_SZ=0x3c0, MM_ORDER=3
│   │   └── kernelsnitch/   — KernelSnitch library
│   │       ├── kernelsnitch.h
│   │       ├── futex_hash.h  — MODIFIED: fixed futex_hashsize
│   │       └── utils.h
│   ├── targets/oppo-find_n2/target.h — All kernel offsets
│   └── preload.so          — Compiled exploit (2.3MB)
└── test_reclaim.c, test_binder.c, test_mcast.c — Test programs
```

### Server (43.139.246.47, user: ubuntu, key: ~/Downloads/11.pem)
```
~/boot-oppo.img              — Copy of boot-2.img (uploaded)
~/vmlinux-oppo.elf           — Raw ELF from boot-2.img (3 symbols only)
~/vmlinux-kernel.bin         — Extracted PE/COFF kernel (stripped, objdumpable)
~/vmlinux-kernel.gz          — (empty/failed extraction)
~/android_kernel_oppo_sm8475-oppo-sm8475_b_16.0.0_find_n2/
    └── vmlinux              — Compiled kernel with symbols (WRONG frame sizes!)
```

### IDA Pro
- **Location**: /Applications/IDA_Pro_9.3/
- **Plugin**: ~/.idapro/plugins/ida_mcp.py
- **MCP Config**: ~/.config/mimocode/mimocode.json
- **IDA Database**: /Users/xiuxiu391/Desktop/oppo/vmlinux.elf.i64
- **Note**: IDA database has imagebase=0x0, functions not named, but disassembly works

---

## 4. Compile & Deploy Commands

### Compile
```bash
NDK=/tmp/ndk_extract/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang
SYSROOT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot
cd /Users/xiuxiu391/Desktop/oppo/exploit

$CC --target=aarch64-linux-android35 --sysroot=$SYSROOT \
  -I. -Isrc -Itargets/oppo-find_n2 \
  -O2 -fPIC -shared \
  -DTARGET_CONFIG_H='"targets/oppo-find_n2/target.h"' \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
  src/preload.c src/su_blob.S src/wallpaper_blob.S \
  -pthread -o preload.so
```

### Deploy & Run
```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

---

## 5. What Was Tried and Failed

### KernelSnitch futex_hashsize Fix (SUCCESS)
- **Problem**: CONFIG_NR_CPUS=32, possible=0-7, online=6. Kernel uses num_possible_cpus()=8, but user-space used sysconf(_SC_NPROCESSORS_ONLN)=6.
- **Fix**: In `futex_hash.h`, changed `futex_init()` to use `_SC_NPROCESSORS_CONF` with `roundup_pow_of_two`.
- **Result**: KernelSnitch now finds mm_struct successfully.

### Binder ioctl Approach (FAILED)
- **Problem**: errno=13 (EACCES) — shell user has no permission to /dev/binder
- **Result**: Completely blocked on Android

### pselect Approach (FAILED)
- **Problem**: fd_set data at stack_top-0x1f8, waiter at stack_top-0x358
- **Gap**: 352B — fd_set cannot reach waiter
- **NFDS=1024**: fd_set moved to heap (kvmalloc), not on stack
- **NFDS=320**: waiter in output area (res_ex), user can't control it

### process_vm_readv Approach (FAILED)
- **Problem**: Frame only 160B (sys 0x10 + process_vm_rw 0x90)
- **Gap**: 696B — way too shallow

---

## 6. Key Technical Details

### GhostLock Vulnerability (CVE-2026-43499)
- `remove_waiter()` clears `current->pi_blocked_on` instead of `waiter->task->pi_blocked_on`
- Affects Linux 2.6.39 to 7.1, requires CONFIG_FUTEX_PI=y
- Trigger: 3 futex words + 3 threads → PI dependency cycle → -EDEADLK → buggy rollback

### Slide Mechanism
1. KernelSnitch leaks mm_struct address
2. SKB payload placed at page_base with fake waiter data
3. GhostLock creates dangling pi_blocked_on pointer
4. **BLOCKED HERE**: Stack reclaim syscall needed to place fake waiter at pi_blocked_on location
5. setpriority triggers PI chain walk → writes to boot_id
6. Read /proc/sys/kernel/random/boot_id → leak kernel base

### Boot Image Analysis
- Android boot image header v4, kernel at offset 0x1000
- Kernel is PE/COFF ARM64 format (not raw gzip)
- extract-vmlinux fails on this format
- Use: `python3 -c "..." ` to extract kernel from boot image

---

## 7. What Needs to Be Done Next

### Priority 1: Find the Right Stack Reclaim Method
The core problem is finding a syscall that writes user-controlled data at **stack_top - 0x358** (856B from kernel stack top).

**Candidate approaches to try:**
1. **nfsetsockopt** — Netfilter setsockopt may have deeper call chain with user data at right offset
2. **io_uring_setup** — Checked: only 272B total, not deep enough
3. **PR_SET_MM_MAP with CAP_SYS_PTRACE helper** — Need helper with elevated privileges
4. **Brute-force NFDS values** — Test NFDS=320 (fd_set on stack, waiter at res_ex) to see if any value makes waiter land in input area
5. **Wait for NebuSec Android blog** — They explicitly said "next blog will discuss how to exploit GhostLock on Android"

### Priority 2: If Stack Reclaim Found
1. Implement in slide.c
2. Compile and test on device
3. Verify boot_id leak (should be kernel base address)

### Priority 3: Complete Exploit Chain
Once KASLR bypass works:
1. pipe.c — Physical R/W via pipe buffer
2. fops.c — Fake fops, CFI bypass
3. root.c — Privilege escalation (patch cred + SELinux)

---

## 8. Suggested Skills

- **diagnosing-bugs** — Debug why stack reclaim methods fail
- **deep-research** — Research Android binder/stack reclaim internals
- **super-research** — Mode: experiment loop — systematically test different NFDS values and stack reclaim methods

---

## 9. NebuSec Writeup Reference

The official GhostLock writeup is at: https://nebusec.ai/research/ionstack-part-2/

Key insights from the writeup:
- On x86 Linux: uses PR_SET_MM_MAP for stack reclaim (EPERM on Android)
- Uses prefetch for KASLR leak (KPTI off, but KPTI is ON on our device)
- Uses CEA (CPU Entry Area) for controlled memory at known address (x86 only, not ARM64)
- Uses inet6_protos[IPPROTO_UDP] as write target
- **They explicitly said**: "next blog will discuss how to exploit GhostLock on Android, reclaiming stack frame, bypassing both ASLR and CFI"
- PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c

Their PoC tests 8 stack reclaim methods including pselect, process_vm, setsockopt, keyctl, timerfd+fcntl, and futex operations. The pselect method uses NFDS=256 which is different from our approach.

---

## 10. Device Info

- **Phone**: OPPO Find N2, serial=84cb96e2
- **USB**: Connected via adb
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build fingerprint**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_NR_CPUS=32**, possible=0-7, online=6
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)
