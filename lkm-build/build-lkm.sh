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
# ★ 本脚本稍后会 cd 进内核树；存根目录必须在【那之前】解析成绝对路径，
#   否则 '$(dirname "$0")/stubs/…' 会相对内核树解析 ⇒ cp: No such file or directory（CI run 37384268383 就是这么挂的）。
STUBS="$(cd "$(dirname "$0")" && pwd)/stubs"

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
# ── ★ vermagic 必须与设备内核【逐字一致】，否则 flags=0 也过不去 ──────────────
# 设备内核 UTS_RELEASE = 5.10.236-android12-9-o-g74d132f4467a（shipped build）。
# 直接源码构建会得到 5.10.236-<githash>-dirty，只差这一段 ⇒ check_modinfo() 拒绝。
# 而本内核没有 CONFIG_MODULE_FORCE_LOAD，所以 finit_module(flags=3/IGNORE_VERMAGIC)
# 走 try_to_force_load() 会【恒定】返回 ENOEXEC —— flags=3 这条路在本机是死的。
# 因此：把 LOCALVERSION 钉死 + 清掉 setlocalversion 的 git 尾巴，然后用 flags=0 装载。
VO="${VERMAGIC_TARGET:-5.10.236-android12-9-o-g74d132f4467a}"
if grep -q '^CONFIG_LOCALVERSION=' .config 2>/dev/null; then
  sed -i "s|^CONFIG_LOCALVERSION=.*|CONFIG_LOCALVERSION=\"${VO#5.10.236}\"|" .config
elif grep -q '^# CONFIG_LOCALVERSION is not set' .config 2>/dev/null; then
  sed -i "s|^# CONFIG_LOCALVERSION is not set|CONFIG_LOCALVERSION=\"${VO#5.10.236}\"|" .config
else
  echo "CONFIG_LOCALVERSION=\"${VO#5.10.236}\"" >> .config
fi
rm -f .scmversion && touch .scmversion     # 让 scripts/setlocalversion 输出空 ⇒ UTS_RELEASE 不含 git hash
echo "== vermagic 目标: ${VO} SMP preempt mod_unload modversions aarch64"
grep -n '^CONFIG_LOCALVERSION' .config | head -2

make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare

# ── ★ 生成内核符号表 Module.symvers（否则 modpost 会跳过未解析符号检查）──────────
# 症状链（实测）：没有 Module.symvers/vmlinux 符号 ⇒
#   "WARNING: Symbol version dump "Module.symvers" is missing."
#   "WARNING: modpost: Symbol info of vmlinux is missing. Unresolved symbol check will be entirely skipped."
#   ⇒ 产出的 kernelsu.ko 带着内核里并不存在的符号引用
#   ⇒ 设备上 finit_module(fd, flags=0) 返回 errno=2 ENOENT（simplify_symbols 找不到符号）
# 所以这里先把内核本体编出来（vmlinux + modules 会经 modpost 产出 Module.symvers）。
# CI 上这一步比较久（20-40 分钟）但在 6 小时限额内；失败也不致命，只是模块会继续 ENOENT。
echo "== build the kernel body so Module.symvers exists (unresolved-symbol checking) =="
if make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- vmlinux 2>&1 | tail -20; then
  echo "vmlinux OK"
else
  echo "!! vmlinux build failed - continuing (module will still ENOENT on load)"
fi
if [ -f Module.symvers ]; then
  echo "== Module.symvers present: $(wc -l < Module.symvers) exported symbols =="
else
  echo "!! Module.symvers still missing - modpost will not validate symbols"
fi

echo "== generate the SELinux generated headers (module-only builds skip them) =="
# KernelSU's infra/file_wrapper.c includes security/selinux/include/objsec.h, which in turn
# includes the GENERATED flask.h / av_permissions.h.  Those are made by
# scripts/selinux/genheaders/genheaders, invoked by a rule inside security/selinux/Makefile - which
# an external (M=) module build never descends into, so the header was never produced.  Naming the
# target from the top level fails ("No rule to make target 'security/selinux/flask.h'") because the
# rule lives in the subdirectory's Makefile: descend into the directory instead, and kbuild will
# build the genheaders host tool and emit both headers.
make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- security/selinux/
ls -l security/selinux/flask.h security/selinux/av_permissions.h

# ── ★ 把 feature/selinux_hide.c 换成空实现存根（去掉未导出的 SELinux 内部符号）──────
# 实测（/data/local/tmp/rw*.log，06:16）：
#     mt99M: ko fd=8 rewound->0 size=6430784
#     mt97: finit_module(fd=8 preopened, flags=0) ret=-1 errno=2 (ENOENT)
# ENOENT 发生在 simplify_symbols()：vermagic（check_modinfo）与 forced-load 两道门都已经过了，
# 纯粹是模块需要的某个符号内核没导出。对 kernelsu.ko 做 .symtab 扫描（oppo/findsym.py）：
# 201 个未定义符号，而其中【全部】SELinux 内部符号都来自这一个文件：
#     avc_has_perm · avc_ss_reset · avtab_alloc/destroy/insert_nonunique/search_node(_next)
#     ebitmap_get_bit · ebitmap_set_bit
# 厂商内核（5.10.236-android12-9-o-g74d132f4467a）没有 EXPORT_SYMBOL 这些。
# 该文件只实现"隐藏痕迹"；root 本身、manager 授权、su 交接、mount namespace 都在别处，
# 所以换成只提供 ksu_selinux_hide_init/_exit 的存根不影响拿到 KernelSU root。
echo "== replace feature/selinux_hide.c with the no-SELinux-internals stub =="
cp -f "$STUBS/selinux_hide_stub.c" "$KSU/kernel/feature/selinux_hide.c"
# ★ 断言必须【跳过注释行】：存根文件头的说明里就写着那几个符号名，
#   直接 grep 全文会把注释当代码 ⇒ 误判 "stub did not take" ⇒ 构建被自己判死
#   （CI run 37385273046 就是这么挂的 ✓）
if grep -vE '^[[:space:]]*(\*|/\*|//)' "$KSU/kernel/feature/selinux_hide.c" \
     | grep -qE 'avc_has_perm|avc_ss_reset|avtab_|ebitmap_'; then
  echo "  !! stub did not take (SELinux internals still referenced in CODE)"; exit 1
fi
echo "  stub in place, no SELinux-internal references in code"

# ── ★ kernel/selinux/ 里还有两个文件在碰 SELinux 内部（第二次实测发现的）────────
# 用【已带 selinux_hide 存根】的模块扫 .symtab（findsym2.py）：avc_has_perm 已清零、
# 体积 6,430,784 → 5,953,296 B，但还剩 8 个：avc_ss_reset + avtab_*(5) + ebitmap_*(2)。
# grep 追源：sepolicy.c 17 处、rules.c 4 处。两者都只服务"策略注入/隐藏痕迹"，
# 与拿到 root 无关；而 selinux.c（实现 setup_selinux/setup_ksu_cred）是干净的、必须保留。
echo "== replace kernel/selinux/{sepolicy.c,rules.c} with internals-free stubs =="
for pair in "sepolicy_stub.c:sepolicy.c" "rules_stub.c:rules.c"; do
  s="${pair%%:*}"; d="${pair##*:}"
  cp -f "$STUBS/$s" "$KSU/kernel/selinux/$d"
  echo "  $d <- $s"
done
if grep -vE '^[[:space:]]*(\*|/\*|//)' "$KSU/kernel/selinux/sepolicy.c" "$KSU/kernel/selinux/rules.c" \
     | grep -qE 'avc_ss_reset|avtab_|ebitmap_'; then
  echo "  !! stubs did not take (SELinux internals still referenced in CODE)"; exit 1
fi
echo "  selinux.c untouched (clean, needed for root); sepolicy.c/rules.c stubbed"

echo "== build kernelsu module (external module against the vendor tree) =="
# KernelSU's kernel/Kbuild builds kernelsu.o under obj-$(CONFIG_KSU); passing CONFIG_KSU=m on
# the command line is enough for an external-module build, no Kconfig integration required.
make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
     M="$KSU/kernel" CONFIG_KSU=m KSU_EXPECTED_SIZE="${KSU_EXPECTED_SIZE:-}" \
     KSU_EXPECTED_HASH="${KSU_EXPECTED_HASH:-}" modules

# ── ★ 第二个版本：最小 KernelSU（去掉 manager/policy 集成）────────────────────────
# 动机（实测）：完整版在设备上 finit_module(fd, flags=0) 返回 errno=2 ENOENT，
# 即 simplify_symbols() 找不到某个符号 —— manager/policy 那块引用的内核符号最多
# （而且 CI 缺 Module.symvers，modpost 根本没能校验过引用）。编一个最小版：
#   · 若最小版能装载 ⇒ 说明就是某个 feature 引用了未导出符号，可逐块二分
#   · 若最小版也 ENOENT ⇒ 是核心符号问题，就要靠 Module.symvers（见上面 vmlinux 那步）
echo "== second artefact: minimal KernelSU (no manager / no policy) =="
if make -j"$(nproc)" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
     M="$KSU/kernel" CONFIG_KSU=m CONFIG_KSU_DISABLE_MANAGER=y CONFIG_KSU_DISABLE_POLICY=y \
     KSU_EXPECTED_SIZE="${KSU_EXPECTED_SIZE:-}" KSU_EXPECTED_HASH="${KSU_EXPECTED_HASH:-}" modules 2>&1 | tail -12; then
  if [ -f "$KSU/kernel/kernelsu.ko" ]; then
    cp -f "$KSU/kernel/kernelsu.ko" ./kernelsu.minimal.ko
    echo "== minimal artefact: $(stat -c %s ./kernelsu.minimal.ko) bytes =="
    tr -c '[:print:]' '\n' < ./kernelsu.minimal.ko | grep -m1 '^vermagic='
  fi
else
  echo "!! minimal build failed - only the full module will ship"
fi

echo "== locate the artefact =="
find "$KSU/kernel" "$KSRC" -maxdepth 3 -name 'kernelsu.ko' -printf '%p  %s bytes\n' 2>/dev/null || true
ls -l "$KSU/kernel/kernelsu.ko" 2>/dev/null || {
  echo "!! kernelsu.ko not found - dumping module dir"; find "$KSU/kernel" -name '*.ko' -o -name '*.o' | head -20; exit 1; }

echo "== sanity: does the module embed the vendor kernel's build id? =="
llvm-nm --defined-only "$KSU/kernel/kernelsu.ko" 2>/dev/null | head -5 || true
echo "OK"