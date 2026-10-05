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
 * handling all live elsewhere (kernel/core, kernel/sucompat, kernel/feature/*).
 * Only trace-hiding is lost.
 *
 * Build wiring: lkm-build/build-lkm.sh copies this file over
 * <KernelSU>/kernel/feature/selinux_hide.c before invoking make/CI.
 */

#include <linux/types.h>

void ksu_selinux_hide_init(void)
{
}

void ksu_selinux_hide_exit(void)
{
}