/* SPDX-License-Identifier: GPL-2.0 */
/*
 * STUB replacement for kernel/feature/selinux_hide.c
 *
 * WHY THIS EXISTS
 * ---------------
 * The real selinux_hide.c implements KernelSU's "hide traces" feature by poking
 * SELinux *implementation internals* directly:
 *
 *     avc_has_perm, avc_ss_reset, avtab_alloc, avtab_destroy,
 *     avtab_insert_nonunique, avtab_search_node, avtab_search_node_next,
 *     ebitmap_get_bit, ebitmap_set_bit
 *
 * None of those are EXPORT_SYMBOL()'d by the OPPO SM8475 vendor kernel
 * (5.10.236-android12-9-o-g74d132f4467a), and this kernel is built without
 * CONFIG_MODULE_FORCE_LOAD.  Consequence, measured on-device (rw*.log, 06:16):
 *
 *     mt99M: ko fd=8 rewound->0 size=6430784
 *     mt97: finit_module(fd=8 preopened, flags=0) ret=-1 errno=2 (ENOENT)
 *
 * ENOENT here is the loader failing in simplify_symbols(): the vermagic check
 * (check_modinfo) and the forced-load path have ALREADY passed, so the module is
 * rejected purely because a symbol it needs is not exported.  The .symtab scan
 * (oppo/findsym.py) shows 201 undefined symbols, and every SELinux-internal one
 * traces back to this single file.
 *
 * Removing the feature costs nothing that matters for obtaining KernelSU root:
 * root itself, the manager authorisation, the su hand-off and the mount namespace
 * handling all live elsewhere (kernel/core, kernel/sucompat, kernel/feature/).
 * Only trace-hiding is lost.
 *
 * Build wiring: lkm-build/build-lkm.sh copies this file over
 * <KernelSU>/kernel/feature/selinux_hide.c before invoking make/CI.
 */

#include <linux/types.h>

/* ★★★ 这三个是内核实测点名的最后 3 个 Unknown symbol（err -2）：
 *     kernelsu: Unknown symbol ksu_selinux_hide_handle_post_fs_data (err -2)
 *     kernelsu: Unknown symbol ksu_selinux_hide_drop_backup_if_unused (err -2)
 *     kernelsu: Unknown symbol ksu_selinux_hide_handle_second_stage (err -2)
 *   它们是【KernelSU 自己】的函数（kernel/feature/selinux_hide.h:6-8 声明），
 *   被 kernel/runtime/boot_event.c 与 kernel/runtime/ksud_integration.c 调用；
 *   原来的存根只提供了 init/_exit ⇒ 这三处就成了无法解析的外部符号 ✗。
 *   签名是 void f(void)，补空实现即可 —— 不需要任何内核导出 ✓
 *   （只要 shim 把其余 46 个内核符号在运行时解析掉，就只差这三个了） */
void ksu_selinux_hide_drop_backup_if_unused(void)
{
}

void ksu_selinux_hide_handle_second_stage(void)
{
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
}

void ksu_selinux_hide_init(void)
{
}

void ksu_selinux_hide_exit(void)
{
}