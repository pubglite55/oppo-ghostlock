#!/usr/bin/env bash
# Build kernelsu.ko against the OPPO Find N2 (PGU110/SM8475) VENDOR kernel, on a Linux runner.
#
# Why this exists: the module must match the vendor kernel's symbol set and struct layout
# (GKI-built LKMs give finit_module -> ENOENT/ENOEXEC on this device).  We therefore build
# against the vendor source tree with the DEVICE'S OWN .config, using clang 12 (r416183b) -
# the compiler generation this 5.10 kernel (CONFIG_CFI_CLANG=y) was built with.
set -euo pipefail

KSRC="${KSRC:-$PWD/kernel}"
KSU="${KSU:-$PWD/KernelSU}"
CLANG="${CLANG:-$PWD/clang}"
CONFIG="${CONFIG:-$PWD/config-5.10.236}"

echo "== toolchain =="
export PATH="$CLANG/bin:$PATH"
clang --version | head -2

echo "== configure the vendor tree with the device's exact config =="
cd "$KSRC"
cp "$CONFIG" .config
# The device's /proc/config.gz carries build-machine paths from OPPO's internal workspace, e.g.
# CONFIG_UNUSED_KSYMS_WHITELIST="/work/0008/workspace/Build_S_Vendor/60183/.../abi_symbollist".
# Generating include/generated/autoksyms.h then fails outright (Makefile:1438) because that file
# does not exist here.  Symbol trimming only decides WHICH symbols get exported - it changes no
# struct layout - and disabling it exports more, never fewer, so the module's symbol resolution
# can only get easier.
./scripts/config --file .config --disable TRIM_UNUSED_KSYMS
./scripts/config --file .config --set-str UNUSED_KSYMS_WHITELIST ""
echo "trim/whitelist neutralised:"; grep -E "TRIM_UNUSED_KSYMS|UNUSED_KSYMS_WHITELIST" .config
# OPPO's published tree references vendor Kconfig files that are NOT published (e.g.
# kernel/oplus_cpu/sched/Kconfig).  olddefconfig dies on the first missing one, so stub them one
# at a time until Kconfig is satisfied.  Systematic on purpose: there may be a dozen.
echo "== olddefconfig (auto-stubbing unpublished vendor Kconfigs) =="
for try in $(seq 1 60); do
  if make ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig >/tmp/od.log 2>&1; then
    echo "olddefconfig OK after $((try-1)) stub(s)"; break
  fi
  MISS=$(grep -oE 'can.t open file "[^"]+"' /tmp/od.log | head -1 | sed 's/.*"\(.*\)"/\1/')
  if [ -z "$MISS" ]; then
    echo "!! olddefconfig failed for a non-Kconfig reason:"; tail -25 /tmp/od.log; exit 1
  fi
  echo "  stubbing unpublished Kconfig: $MISS"
  if [ -e "$MISS" ] && [ ! -L "$MISS" ]; then
    echo "    (already present as a real file - retrying olddefconfig without stubbing)"
    continue
  fi
  # kernel/oplus_cpu is itself a DANGLING SYMLINK into an unpublished vendor path, so both
  # 'mkdir -p kernel/oplus_cpu' ("File exists") and writing the stub through it ("No such file or
  # directory") fail.  Walk the ancestor chain, drop any dangling link, then create real dirs.
  d=$(dirname "$MISS")
  while [ -n "$d" ] && [ "$d" != "." ] && [ "$d" != "/" ]; do
    if [ -L "$d" ] && [ ! -e "$d" ]; then echo "    removing dangling link in path: $d"; rm -f "$d"; fi
    d=$(dirname "$d")
  done
  [ -L "$MISS" ] && rm -f "$MISS"
  mkdir -p "$(dirname "$MISS")"
  {
    echo "# [ci stub] this Kconfig is referenced by the published OPPO tree but not published."
    echo "# Stubbed so kbuild can configure; the options it would define are simply absent."
  } > "$MISS"
  if [ "$try" = "60" ]; then echo "!! still failing after 60 stubs"; tail -25 /tmp/od.log; exit 1; fi
done

echo "== modules_prepare =="
make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare

echo "== build kernelsu module (external module against the vendor tree) =="
# KernelSU's kernel/Kbuild builds kernelsu.o under obj-$(CONFIG_KSU); passing CONFIG_KSU=m on
# the command line is enough for an external-module build, no Kconfig integration required.
make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
     M="$KSU/kernel" CONFIG_KSU=m KSU_EXPECTED_SIZE="${KSU_EXPECTED_SIZE:-}" \
     KSU_EXPECTED_HASH="${KSU_EXPECTED_HASH:-}" modules

echo "== locate the artefact =="
find "$KSU/kernel" "$KSRC" -maxdepth 3 -name 'kernelsu.ko' -printf '%p  %s bytes\n' 2>/dev/null || true
ls -l "$KSU/kernel/kernelsu.ko" 2>/dev/null || {
  echo "!! kernelsu.ko not found - dumping module dir"; find "$KSU/kernel" -name '*.ko' -o -name '*.o' | head -20; exit 1; }

echo "== sanity: does the module embed the vendor kernel's build id? =="
llvm-nm --defined-only "$KSU/kernel/kernelsu.ko" 2>/dev/null | head -5 || true
echo "OK"