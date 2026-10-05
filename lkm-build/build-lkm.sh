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
make ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig

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