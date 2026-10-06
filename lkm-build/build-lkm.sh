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

# ── ★★★ 修复 ENOENT 的第一根源：SCM 版本必须与设备内核【逐字一致】─────────────
# 设备 uname -r = 5.10.236-android12-9-o-g74d132f4467a  ⇒ 内核 SCM 串 = g74d132f4467a
# 而我的模块出厂带 .modinfo scmversion=g932014ab5b2c-dirty ✗（我的源码树 git 尾巴 + -dirty）
# 设备内核 CONFIG_MODULE_SCMVERSION=y ⇒ 装载时比对 SCM 版本 ⇒ 不一致即 -ENOENT。
# 修法：在编模块前把 include/config/scmversion 钉成内核那个值（setlocalversion 会读它）。
SCM_VER="${SCM_VER:-g74d132f4467a}"
mkdir -p include/config
printf '%s' "$SCM_VER" > include/config/scmversion
echo "== scmversion pinned -> $(cat include/config/scmversion)（必须等于设备 uname -r 的 g 尾巴）"

# ── ★★★ 修复 ENOENT 的第二根源：__versions 全空（modversions CRC 表缺失）───────
# 实测证据（2026-10-06）：新 .ko 的 __versions 段 size=0，而设备内核
#   CONFIG_MODVERSIONS=y + CONFIG_MODULE_SCMVERSION=y + CONFIG_TRIM_UNUSED_KSYMS=y
#   ⇒ 每个符号都要查 CRC、还要 SCM 版本逐字一致 ⇒ 缺一即 finit_module 返回 -ENOENT。
# 根因：本地/CI 都没有 Module.symvers ⇒ modpost 跳过符号版本生成 ⇒ __versions 空。
# 修法：必须先把内核本体编出来拿 Module.symvers，再编模块；并断言 __versions 非空。
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

echo "== ★ 接入 ksu_syms_compat（non-GKI 运行时符号解析）=="
# 为什么：厂商内核不导出 49 个核心符号，内核实测点名：
#   "kernelsu: Unknown symbol commit_creds (err -2)" ×49 ⇒ finit_module 返回 -ENOENT。
# 设备内核具备 CONFIG_KPROBES=y + CONFIG_KALLSYMS_ALL=y ⇒ 可在运行时解析。
# 关键自举：KernelSU 自带的 infra/symbol_resolver.c 直接调用 kallsyms_lookup_name，
# 而它本身没被导出 ⇒ 必须先用 kprobe 拿到它（register_kprobe 内部按名字查，不受 EXPORT 限制）。
cp -f "$STUBS/ksu_syms_compat.c" "$KSU/kernel/infra/ksu_syms_compat.c"
cp -f "$STUBS/ksu_syms_compat.h" "$KSU/kernel/infra/ksu_syms_compat.h"
KB="$KSU/kernel/Kbuild"
if ! grep -q 'infra/ksu_syms_compat.o' "$KB"; then
  printf '\nkernelsu-objs += infra/ksu_syms_compat.o\n' >> "$KB"
fi
if ! grep -q 'ksu_syms_compat.h' "$KB"; then
  printf '\nccflags-y += -include $(src)/infra/ksu_syms_compat.h\n' >> "$KB"
fi
echo "  Kbuild 尾部："; tail -4 "$KB"

# ── ★ 自检（替代旧的“宏数 ≥ 44”断言）：现在走【真转发定义】路线 ───────────────
# ① 头文件里不允许再有任何 #define X KSU_SYM(X)（宏路线已废弃）
if grep -qE '^#define[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+KSU_SYM' "$KSU/kernel/infra/ksu_syms_compat.h"; then
  echo "  !! 头文件里仍有 #define X KSU_SYM(X) 宏残留，宏路线未清干净"; exit 1
fi
# ② 44 个符号每一个都必须在 .c 里有【运行时解析点】（ksu_sym_ptr("名") 或
#    ksu_sym_ptr 内部的 g_kln("名")——selinux_blob_sizes 因自举不能递归调用）
SYMS_LIST="__arm64_sys_setns __flush_dcache_area __set_fixmap __tracepoint_sys_enter \
abort_creds alloc_file_pseudo alloc_uid change_pid commit_creds copy_from_user_nofault \
copy_to_kernel_nofault copy_to_user_nofault dentry_open ext4_unregister_sysfs groups_alloc \
groups_free groups_sort init_mm iterate_dir kallsyms_lookup kallsyms_lookup_name \
kallsyms_lookup_size_offset kernel_read kernel_write ksys_unshare mntns_operations ns_get_path \
override_creds path_get path_mount prepare_creds revert_creds seccomp_filter_release \
security_inode_init_security_anon security_release_secctx security_secctx_to_secid \
security_secid_to_secctx selinux_blob_sizes selinux_state set_fs_pwd set_groups \
static_key_count strncpy_from_user_nofault task_work_add"
RESOLVED=0; MISSING=""
for s in $SYMS_LIST; do
  if grep -qE "(ksu_sym_ptr|g_kln)\(\"$s\"\)" "$KSU/kernel/infra/ksu_syms_compat.c"; then
    RESOLVED=$((RESOLVED + 1))
  else
    MISSING="$MISSING $s"
  fi
done
echo "  符号运行时解析点 = $RESOLVED（应为 44）"
[ -z "$MISSING" ] || { echo "  !! 以下符号没有解析点：$MISSING"; exit 1; }

# ── ★ 数据符号使用点改写：不能同名转发，只能在使用处改为调用访问器 ────────────
# 内核源码树里的真实声明（供签名核对）：
#   include/linux/mm_types.h:612   extern struct mm_struct init_mm;
#   include/linux/proc_ns.h:33     extern const struct proc_ns_operations mntns_operations;
#   security/selinux/include/security.h:113 extern struct selinux_state selinux_state;
#   include/trace/events/syscalls.h  __tracepoint_sys_enter（DECLARE_TRACE token-paste 生成）
# 这些符号在内核源码里的用法很少（每个 1-2 个文件），逐个改写并断言：
echo "== ★ 改写数据符号使用点（同名宏 → 访问器/助手）=="
PM="$KSU/kernel/hook/arm64/patch_memory.c"
SM="$KSU/kernel/infra/su_mount_ns.c"
SC="$KSU/kernel/selinux/selinux.c"
HM="$KSU/kernel/hook/syscall_hook_manager.c"

# ① init_mm —— phys_from_virt() 里 struct mm_struct *mm = &init_mm;
sed -i 's/struct mm_struct \*mm = &init_mm;/struct mm_struct *mm = ksu_get_init_mm();/' "$PM"
grep -q 'ksu_get_init_mm()' "$PM" || { echo "  !! init_mm 改写失败($PM)"; exit 1; }

# ② mntns_operations —— ns_get_path(&ns_path, pid1_task, &mntns_operations);
sed -i 's/&mntns_operations/ksu_get_mntns_operations()/' "$SM"
grep -q 'ksu_get_mntns_operations()' "$SM" || { echo "  !! mntns_operations 改写失败($SM)"; exit 1; }

# ③ selinux_state —— setenforce()/getenforce() 里的 selinux_state.xxx（只读/写字段，非类型）
sed -i 's/\bselinux_state\b/(*ksu_get_selinux_state())/g' "$SC"
SCN=$(grep -c 'ksu_get_selinux_state()' "$SC")
[ "$SCN" -ge 3 ] || { echo "  !! selinux_state 改写不足($SC：$SCN 处)"; exit 1; }

# ④ __tracepoint_sys_enter —— register_trace_prio_sys_enter / unregister_trace_sys_enter
sed -i 's/register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN)/ksu_tp_register_sys_enter(ksu_sys_enter_handler)/' "$HM"
sed -i 's/unregister_trace_sys_enter(ksu_sys_enter_handler, NULL)/ksu_tp_unregister_sys_enter(ksu_sys_enter_handler)/' "$HM"
grep -q 'ksu_tp_register_sys_enter' "$HM" || { echo "  !! __tracepoint_sys_enter 注册点改写失败($HM)"; exit 1; }
grep -q 'ksu_tp_unregister_sys_enter' "$HM" || { echo "  !! __tracepoint_sys_enter 注销点改写失败($HM)"; exit 1; }
# 改写后，这四个文件里不应再残留对这些内核符号的【直接引用】
for f in "$PM" "$SM" "$SC" "$HM"; do
  if grep -nE '[^A-Za-z0-9_](&init_mm|&mntns_operations|[^A-Za-z0-9_]selinux_state\.|register_trace_prio_sys_enter|unregister_trace_sys_enter)' "$f" \
      | grep -v 'ksu_get_init_mm\|ksu_get_mntns_operations\|ksu_get_selinux_state\|ksu_tp_register_sys_enter\|ksu_tp_unregister_sys_enter'; then
    echo "  !! $f 里仍有未改写的直连引用（见上）"; exit 1
  fi
done
echo "  数据符号使用点改写完成：patch_memory.c / su_mount_ns.c / selinux.c / syscall_hook_manager.c"

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

# ── ★★★ 极简装载器 ksu_min_load.ko（绕开 ksud 进程风暴）────────────────────────
# 动机（器件侧实测）：exploit 走到装载段会拉起 ksud 的进程风暴 ⇒ 厂商内核
#   "BUG: workqueue lockup - pool cpus=… nice=-20 stuck for 49s/57s/88s" ⇒ panic
#   （CPU 6 / 4 / 不钉 三种配置均复现）；而【绕开 ksud 的那一发 crash4.log 归零】✓
#   ⇒ 风暴就是 panic-on-wq-lockup 的触发源。
# 本模块只做三件事、不制造风暴（详见 lkm-build/minload/ksu_min_load.c）：
#   ① kprobe 取 kallsyms_lookup_name（自举）
#   ② WRITE_ONCE(*selinux_state, false) ⇒ permissive
#   ③ call_usermodehelper_setup/exec（本来就导出）只跑【一句 /system/bin/insmod -f <ko>】
#   然后 return -E2BIG 让内核把本模块卸载（不留痕迹）
echo "== build minimal late-loader (ksu_min_load.ko, no ksud storm) =="
# ★ 必须用【cd 之前】就取好的绝对路径：脚本开头有 STUBS="$(cd "$(dirname "$0")" && pwd)/stubs"
#   它的 dirname 就是仓库里的 lkm-build ✓
#   （实测两次翻车：先用了 $(dirname $0)/minload ⇒ cd 后 "minload dir missing" ✗；
#     再用了 $(cd $(dirname $0) && pwd) ⇒ cd 后 "cd: lkm-build: No such file or directory" ✗）
ROOT="$(dirname "$STUBS")"
ML="$ROOT/minload"
if [ -d "$ML" ]; then
  if make -j"$(nproc)" -C "$ML" KDIR="$KSRC" > /tmp/minload.log 2>&1; then
    if [ -f "$ML/ksu_min_load.ko" ]; then
      cp -f "$ML/ksu_min_load.ko" "$ROOT/ksu_min_load.ko"
      # ★ 必须同时放进 out/ —— 工作流的"收集产物"只捡 out/ 下的东西
      cp -f "$ML/ksu_min_load.ko" "$ROOT/out/ksu_min_load.ko"
      echo "== ksu_min_load.ko: $(stat -c %s "$ROOT/ksu_min_load.ko") bytes =="
      tr -c '[:print:]' '\n' < "$ROOT/ksu_min_load.ko" | grep -m1 '^vermagic=' || true
      echo "-- its undefined symbols（应极少、且都在内核里存在）--"
      llvm-nm -u "$ROOT/ksu_min_load.ko" 2>/dev/null | head -25 || true
    else
      echo "  !! ksu_min_load.ko not produced"; tail -20 /tmp/minload.log
    fi
  else
    echo "  !! minload build failed - tail:"; tail -30 /tmp/minload.log
  fi
else
  echo "  !! minload dir missing: $ML"
fi