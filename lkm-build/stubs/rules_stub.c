// SPDX-License-Identifier: GPL-2.0
/*
 * STUB replacement for kernel/selinux/rules.c
 *
 * WHY: the real rules.c calls avc_ss_reset() (both the pre- and post-6.x
 * signatures) to flush the AVC after injecting KernelSU's SELinux rules.
 * avc_ss_reset is NOT EXPORT_SYMBOL'd by the OPPO SM8475 vendor kernel
 * (5.10.236-android12-9-o-g74d132f4467a), so keeping the file makes the module
 * carry an undefined symbol and finit_module(flags=0) fails with errno=2
 * ENOENT from simplify_symbols() - the vermagic and forced-load gates already
 * passed.  Confirmed by scanning the module's .symtab (oppo/findsym2.py):
 * with feature/selinux_hide.c stubbed, avc_ss_reset plus the avtab_/ebitmap_
 * family from kernel/selinux/sepolicy.c were the only internals left.
 *
 * COST: none that matters for KernelSU root.  apply_kernelsu_rules() only
 * pushes the ksu/ksu_file types and allow rules into the running policy so
 * traces stay hidden; root, the ksu cred setup, the su hand-off and the mount
 * namespace handling do not depend on it.  The hook is kept as a no-op entry
 * point so the rest of the tree links unchanged.
 */

#include <linux/types.h>

void apply_kernelsu_rules(void)
{
}