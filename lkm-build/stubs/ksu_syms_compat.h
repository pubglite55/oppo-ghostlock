/* ksu_syms_compat.h — non-GKI 符号运行时解析（强制包含头）
 * ────────────────────────────────────────────────────────────────────────────
 * 为什么需要它：厂商 SM8475 内核不 EXPORT KernelSU 用到的 49 个核心符号
 * （commit_creds / prepare_creds / kallsyms_lookup_name / path_mount / init_mm …），
 * 而且开着 CONFIG_TRIM_UNUSED_KSYMS=y ⇒ 模块硬链接它们 ⇒ finit_module 返回 -ENOENT，
 * 内核打印 "kernelsu: Unknown symbol <名> (err -2)" ×49（实测已见）。
 *
 * 但设备内核同时具备：
 *   CONFIG_KPROBES=y  +  CONFIG_KALLSYMS_ALL=y  +  /proc/kallsyms 651630 行
 * ⇒ 这些符号【都存在，只是没导出】⇒ 可在运行时解析（non-GKI 的标准做法）。
 *
 * 手法：register_kprobe() 内部按名字查符号表 ⇒ 连未导出的 kallsyms_lookup_name 都能拿到；
 * 再用它解析其余符号。宏用 typeof(原声明) 取类型 ⇒ 函数与数据符号统一写法；
 * #define X KSU_SYM(X) 里内层的 X 会被预处理器 blue-paint 掉、不再展开 ⇒ 不递归 ✓。
 */
#ifndef _KSU_SYMS_COMPAT_H
#define _KSU_SYMS_COMPAT_H

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/cred.h>
#include <linux/groups.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/static_key.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/task_work.h>
#include <linux/version.h>

void *ksu_sym_ptr(const char *name);

/* typeof(n) = 原声明给出的真实类型 ⇒ 函数退化成函数指针、数据退化成对象指针，统一解引用 */

/* —— 凭据/身份（KernelSU root 与 su 交接的核心路径）—— */
#define commit_creds                KSU_SYM(commit_creds)
#define prepare_creds               KSU_SYM(prepare_creds)
#define override_creds              KSU_SYM(override_creds)
#define revert_creds                KSU_SYM(revert_creds)
#define abort_creds                 KSU_SYM(abort_creds)
#define set_groups                  KSU_SYM(set_groups)
#define groups_alloc                KSU_SYM(groups_alloc)
#define groups_free                 KSU_SYM(groups_free)
#define groups_sort                 KSU_SYM(groups_sort)
#define alloc_uid                   KSU_SYM(alloc_uid)

/* —— kallsyms —— */
#define kallsyms_lookup             KSU_SYM(kallsyms_lookup)
#define kallsyms_lookup_name        KSU_SYM(kallsyms_lookup_name)
#define kallsyms_lookup_size_offset KSU_SYM(kallsyms_lookup_size_offset)

/* —— 命名空间 / 路径（su 的 mount ns 交接）—— */
#define __arm64_sys_setns           KSU_SYM(__arm64_sys_setns)
#define ksys_unshare                KSU_SYM(ksys_unshare)
#define ns_get_path                 KSU_SYM(ns_get_path)
#define mntns_operations            KSU_SYM(mntns_operations)
#define path_get                    KSU_SYM(path_get)
#define path_mount                  KSU_SYM(path_mount)
#define path_umount                 KSU_SYM(path_umount)
#define set_fs_pwd                  KSU_SYM(set_fs_pwd)
#define dentry_open                 KSU_SYM(dentry_open)
#define alloc_file_pseudo           KSU_SYM(alloc_file_pseudo)
#define iterate_dir                 KSU_SYM(iterate_dir)

/* —— 进程 / 任务 —— */
#define change_pid                  KSU_SYM(change_pid)
#define task_work_add               KSU_SYM(task_work_add)
#define seccomp_filter_release      KSU_SYM(seccomp_filter_release)

/* —— 内核内存 / 架构 —— */
#define init_mm                     KSU_SYM(init_mm)
#define __flush_dcache_area         KSU_SYM(__flush_dcache_area)
#define __set_fixmap                KSU_SYM(__set_fixmap)

/* —— 内核读写 —— */
#define kernel_read                 KSU_SYM(kernel_read)
#define kernel_write                KSU_SYM(kernel_write)
#define copy_from_user_nofault      KSU_SYM(copy_from_user_nofault)
#define copy_to_user_nofault        KSU_SYM(copy_to_user_nofault)
#define copy_to_kernel_nofault      KSU_SYM(copy_to_kernel_nofault)
#define strncpy_from_user_nofault   KSU_SYM(strncpy_from_user_nofault)

/* —— LSM / SELinux —— */
#define security_secid_to_secctx    KSU_SYM(security_secid_to_secctx)
#define security_secctx_to_secid    KSU_SYM(security_secctx_to_secid)
#define security_release_secctx     KSU_SYM(security_release_secctx)
#define security_inode_init_security_anon KSU_SYM(security_inode_init_security_anon)
#define selinux_state               KSU_SYM(selinux_state)
#define selinux_blob_sizes          KSU_SYM(selinux_blob_sizes)

/* —— tracepoint / 静态键 —— */
#define __tracepoint_sys_enter      KSU_SYM(__tracepoint_sys_enter)
#define static_key_count            KSU_SYM(static_key_count)

/* —— 文件系统 —— */
#define ext4_unregister_sysfs       KSU_SYM(ext4_unregister_sysfs)

/* —— 我自己的存根没补全的 4 个（实测出现在内核 Unknown-symbol 名单里）—— */
#define handle_sepolicy                              KSU_SYM(handle_sepolicy)
#define ksu_selinux_hide_handle_post_fs_data         KSU_SYM(ksu_selinux_hide_handle_post_fs_data)
#define ksu_selinux_hide_handle_second_stage         KSU_SYM(ksu_selinux_hide_handle_second_stage)
#define ksu_selinux_hide_drop_backup_if_unused       KSU_SYM(ksu_selinux_hide_drop_backup_if_unused)

#endif /* _KSU_SYMS_COMPAT_H */
