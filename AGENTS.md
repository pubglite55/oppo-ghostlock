# Agent Instructions

## What this repo is

Security research project exploiting GhostLock (CVE-2026-43499), a Linux kernel stack UAF via FUTEX_CMP_REQUEUE_PI race. Targets OPPO Find N2 (CPH2413, SM8475, kernel 5.10.236). The exploit chain: Firefox 151 CVE-2026-10702 → preload.so (LD_PRELOAD) → KernelSnitch (mm_struct leak) → GhostLock trigger → pipe physrw → root.

## Build (cross-compile for Android ARM64)

No Makefile exists. Build is a single clang invocation:

```bash
NDK=/tmp/ndk_extract/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang
SYSROOT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot
cd exploit/

$CC --target=aarch64-linux-android35 --sysroot=$SYSROOT \
  -I. -Isrc -Itargets/oppo-find_n2 \
  -O2 -fPIC -shared \
  -DTARGET_CONFIG_H='"targets/oppo-find_n2/target.h"' \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
  src/preload.c src/su_blob.S src/wallpaper_blob.S \
  -pthread -o preload.so
```

Output: `preload.so` (2.3MB shared library). Deploy via `adb push` + `LD_PRELOAD`.

## Key gotchas

- **`TARGET_CONFIG_H` is mandatory** — `offset.h` errors without it. Pass as a `-D` string literal.
- **Two `exploit/src/` dirs exist**: `exploit/src/` (compiled) and `exploit-src/` (reference/older). Always edit `exploit/src/`.
- **Server vmlinux frame sizes are WRONG** — use boot-2.img extracted kernel for frame analysis. `do_futex` frame: 0x1c0 (448B) on device vs 0x130 (304B) on server.
- **KASLR bypass (slide) is blocked** — all 20+ stamp methods failed. Waiter is at `stack_top - 0x358`, no syscall writes user-controlled data at that offset. This is the main blocker.
- **GhostLock trigger does NOT work in standalone tests** — FUTEX_WAIT_REQUEUE_PI returns ETIMEDOUT immediately. Wrong synchronization: CMP_REQUEUE_PI fires after WAIT returns, not while blocked.
- **Firefox 151 required** — CVE-2026-10702 only exists in version 151.0.

## Architecture notes

- **No CI, no linter, no tests** — pure research repo
- **Target-specific offsets** live in `exploit/targets/oppo-find_n2/target.h` (201 lines of #defines, all pahole-verified)
- **KernelSnitch** uses futex hash collisions + ashmem to leak mm_struct. Fixed `futex_hash.h` to use `_SC_NPROCESSORS_CONF` (not `_SC_ONLN`) with `roundup_pow_of_two`.
- **Analysis scripts** in `analysis-scripts/` — `find_deep_chains*.py` for kernel call chain analysis, `inspect_elf.py` / `inspect_text.py` for binary inspection
- **Test programs** in `test-programs/` — standalone tests for futex, binder, pselect, reclaim, seccomp

## Project status

| Stage | Status |
|-------|--------|
| KernelSnitch mm_struct leak | Working |
| SKB payload preparation | Working |
| GhostLock FUTEX PI trigger | Fails (ETIMEDOUT, wrong sync) |
| KASLR bypass (slide) | Blocked (no stamp reaches waiter) |
| pipe physrw | Pending (depends on KASLR) |
| root (cred + SELinux) | Pending (depends on KASLR) |

## Reference docs

- `HANDOFF.md` — detailed session handoff with all technical findings
- `docs/architecture.md` — exploit chain architecture diagram
- `docs/knowledge-notes.md` — SLUB order calc, rt_mutex_waiter layout, boot image format
- `TROUBLESHOOTING.md` — build errors, runtime failures, environment issues
- NebuSec writeup: https://nebusec.ai/research/ionstack-part-2/
- CyberMeowfia PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c
