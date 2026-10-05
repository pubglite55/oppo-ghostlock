// SPDX-License-Identifier: GPL-2.0
/*
 * STUB replacement for kernel/selinux/sepolicy.c
 *
 * WHY: this file implements KernelSU's runtime SEPOLICY INJECTION by reaching
 * into SELinux *implementation internals* that the OPPO SM8475 vendor kernel
 * (5.10.236-android12-9-o-g74d132f4467a) does NOT EXPORT_SYMBOL:
 *
 *     avtab_search_node / avtab_search_node_next / avtab_insert_nonunique
 *     avtab_alloc / avtab_destroy
 *     ebitmap_get_bit / ebitmap_set_bit
 *
 * With the kernel built without CONFIG_MODULE_FORCE_LOAD, an unexported symbol
 * makes finit_module() fail in simplify_symbols() with errno=2 ENOENT - after
 * the vermagic and forced-load gates have already passed.  Measured on-device:
 *
 *     mt99M: ko fd=8 rewound->0 size=6430784
 *     mt97: finit_module(fd=8 preopened, flags=0) ret=-1 errno=2 (ENOENT)
 *
 * A .symtab scan (oppo/findsym2.py) of the module built WITH the
 * feature/selinux_hide.c stub already dropped avc_has_perm and shrank the
 * binary from 6,430,784 to 5,953,296 bytes, leaving exactly these symbols -
 * and they all trace to this file.
 *
 * COST: none that matters for KernelSU root.  This API only rewrites the
 * in-memory SELinux policy (used by the manager's sepolicy ioctl and by
 * apply_kernelsu_rules() for trace-hiding).  Root itself, the ksu cred setup
 * (kernel/selinux/selinux.c - kept as-is), the su hand-off and the mount
 * namespace handling do not go through it.  The functions report failure so
 * callers degrade gracefully.
 */

#include <linux/types.h>
#include <linux/errno.h>

struct policydb;
struct selinux_policy;

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
	return NULL;
}

void ksu_destroy_sepolicy(struct selinux_policy *orig)
{
}

bool ksu_type(struct policydb *db, const char *name, const char *attr)
{
	return false;
}

bool ksu_attribute(struct policydb *db, const char *name)
{
	return false;
}

bool ksu_permissive(struct policydb *db, const char *type)
{
	return false;
}

bool ksu_enforce(struct policydb *db, const char *type)
{
	return false;
}

bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr)
{
	return false;
}

bool ksu_exists(struct policydb *db, const char *type)
{
	return false;
}

bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
	return false;
}

bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
	return false;
}

bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
	return false;
}

bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
	return false;
}

bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
	return false;
}

bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
	return false;
}

bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
	return false;
}

bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
			 const char *obj)
{
	return false;
}

bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
	return false;
}

bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
	return false;
}

bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx)
{
	return false;
}

/*
 * Non-static in sepolicy.c and reachable from outside it, so it must keep
 * existing for the tree to link.  It is a plain kvmalloc/kvfree wrapper that
 * touches no SELinux internals - returning NULL makes callers take their
 * out-of-memory path, which is the honest answer when the policy rewriting
 * this module would have done is disabled anyway.
 */
void *ksu_kvrealloc_compat(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
{
	return NULL;
}