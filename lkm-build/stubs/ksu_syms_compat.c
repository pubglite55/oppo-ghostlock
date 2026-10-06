/* ksu_syms_compat.c — non-GKI 未导出符号的【真转发定义】层
 * ────────────────────────────────────────────────────────────────────────────
 * 为什么用 kprobe 自举：register_kprobe() 在【内核内部】按名字查符号表 ⇒ 不受
 * EXPORT_SYMBOL / CONFIG_TRIM_UNUSED_KSYMS 限制 ⇒ 连 kallsyms_lookup_name 这种
 * 已被移除导出的符号也能拿到（non-GKI 标准技巧）。之后用它解析其余符号。
 *
 * ★ 本文件是“真转发定义”路线的本体：
 *   · 39 个【函数】符号 → 写同名转发定义（首次调用解析并缓存函数指针）。
 *     模块内部因此把这 39 个符号“定义”掉，内核侧不再有未定义引用 ⇒ finit_module
 *     不再因 Unknown symbol 返回 -ENOENT。签名全部取自内核源码树的真实原型。
 *   · 3 个【数据】符号（init_mm / mntns_operations / selinux_state）→ 不同名
 *     访问器，由 build-lkm.sh 在少数使用点改写源码调用（对象身份必须与内核一致）。
 *   · selinux_blob_sizes → 同名对象 + 首次解析时从内核对象 memcpy 一次
 *     （lsm_blob_sizes 是启动后不再变化的偏移量，值拷贝是正确的）。
 *   · __tracepoint_sys_enter → ksu_tp_*_sys_enter() 助手（内部运行时解析
 *     __tracepoint_sys_enter + tracepoint_probe_register_prio/_unregister，
 *     避免再引入新的未导出未定义引用）。
 *   · path_umount → 沿用真转发定义（本颗内核头里没有它的声明）。
 */
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <linux/dcache.h>        /* struct qstr */
#include <linux/proc_ns.h>       /* struct proc_ns_operations */
#include <linux/sched/user.h>    /* struct user_struct / alloc_uid() */
#include <linux/tracepoint.h>    /* struct tracepoint / tracepoint_probe_register_prio() */
#include "ksu_syms_compat.h"

typedef unsigned long (*ksu_kln_t)(const char *);

static ksu_kln_t g_kln;

/* 只做一次；失败也不致命（后面每次 lookup 都会重试一次） */
static void ksu_sym_resolve_kln(void)
{
    struct kprobe kp;
    int ret;

    if (g_kln)
        return;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("ksu_syms: register_kprobe(kallsyms_lookup_name) failed: %d\n", ret);
        return;
    }
    g_kln = (ksu_kln_t)kp.addr;
    unregister_kprobe(&kp);
    pr_info("ksu_syms: resolved kallsyms_lookup_name @ %px\n", (void *)g_kln);
}

/* ── selinux_blob_sizes：同名【对象】───────────────────────────────────────
 * 内核 security/selinux/include/objsec.h 的 selinux_cred()/selinux_inode()/
 * selinux_file() 等 static inline 直接读 selinux_blob_sizes.lbs_* ⇒ 不能改名。
 * 它是 struct lsm_blob_sizes（各 LSM blob 在 ->security 里的偏移），在启动
 * (LSM 注册)之后【不再变化】⇒ 首次解析符号时从内核对象 memcpy 一次即可，
 * 之后所有读都拿到正确偏移。
 * ★ 初始化时机：模块 init 路径里第一次调用转发函数是 core/init.c 的
 *   prepare_creds()（在任何 selinux_cred() 之前），它必然经过 ksu_sym_ptr()
 *   ⇒ selinux_blob_sizes 在第一次被读之前就已填好。 */
struct lsm_blob_sizes selinux_blob_sizes;
static bool g_blob_sizes_ready;

void *ksu_sym_ptr(const char *name)
{
    unsigned long addr;

    if (!g_kln)
        ksu_sym_resolve_kln();
    if (!g_kln) {
        pr_err("ksu_syms: no resolver for '%s'\n", name);
        return NULL;
    }

    addr = g_kln(name);
    if (!addr)
        pr_warn("ksu_syms: symbol '%s' not found in kallsyms\n", name);

    if (!g_blob_sizes_ready) {
        unsigned long sb = g_kln("selinux_blob_sizes");
        if (sb) {
            memcpy(&selinux_blob_sizes, (void *)sb, sizeof(selinux_blob_sizes));
            g_blob_sizes_ready = true;
        }
    }

    return (void *)addr;
}
EXPORT_SYMBOL(ksu_sym_ptr);

/* ── 数据符号访问器（不同名；首次解析后缓存，避免热路径反复查 kallsyms）── */
struct mm_struct *ksu_get_init_mm(void)
{
    static struct mm_struct *p;

    if (!p)
        p = (struct mm_struct *)ksu_sym_ptr("init_mm");
    return p;
}

const struct proc_ns_operations *ksu_get_mntns_operations(void)
{
    static const struct proc_ns_operations *p;

    if (!p)
        p = (const struct proc_ns_operations *)ksu_sym_ptr("mntns_operations");
    return p;
}

struct selinux_state *ksu_get_selinux_state(void)
{
    static struct selinux_state *p;

    if (!p)
        p = (struct selinux_state *)ksu_sym_ptr("selinux_state");
    return p;
}

/* ── __tracepoint_sys_enter 的注册/注销助手 ───────────────────────────────
 * 内核的 register_trace_prio_sys_enter() 是 static inline，展开成
 *   tracepoint_probe_register_prio(&__tracepoint_sys_enter, probe, data, prio)
 * 而 __tracepoint_sys_enter 在 DECLARE_TRACE() 里被 __tracepoint_##name
 * token-pasting 引用 ⇒ 宏改不动它。这里改成运行时解析该对象，
 * 并同样运行时解析 tracepoint_probe_register_prio/_unregister（避免把
 * 这两个符号做成未定义引用——设备内核未必导出它们）。 */
#define KSU_INT_MIN (-2147483647 - 1)

int ksu_tp_register_sys_enter(void (*probe)(void *, struct pt_regs *, long))
{
    static int (*reg)(struct tracepoint *, void *, void *, int);
    struct tracepoint *tp = (struct tracepoint *)ksu_sym_ptr("__tracepoint_sys_enter");

    if (!tp) {
        pr_err("ksu_syms: __tracepoint_sys_enter not found\n");
        return -ENOENT;
    }
    if (!reg) {
        reg = (int (*)(struct tracepoint *, void *, void *, int))ksu_sym_ptr("tracepoint_probe_register_prio");
        if (!reg) {
            pr_err("ksu_syms: tracepoint_probe_register_prio not found\n");
            return -ENOENT;
        }
    }
    return reg(tp, (void *)probe, NULL, KSU_INT_MIN);
}

int ksu_tp_unregister_sys_enter(void (*probe)(void *, struct pt_regs *, long))
{
    static int (*unreg)(struct tracepoint *, void *, void *);
    struct tracepoint *tp = (struct tracepoint *)ksu_sym_ptr("__tracepoint_sys_enter");

    if (!tp)
        return -ENOENT;
    if (!unreg) {
        unreg = (int (*)(struct tracepoint *, void *, void *))ksu_sym_ptr("tracepoint_probe_unregister");
        if (!unreg)
            return -ENOENT;
    }
    return unreg(tp, (void *)probe, NULL);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 39 个函数符号的同名转发定义
 * 签名来源（内核源码树 grep include/）：
 *   cred.h commit_creds/prepare_creds/override_creds/revert_creds/abort_creds/
 *          set_groups/groups_alloc/groups_free/groups_sort
 *   sched/user.h alloc_uid
 *   kallsyms.h kallsyms_lookup/lookup_name/lookup_size_offset
 *   fs.h dentry_open/iterate_dir/kernel_read/kernel_write
 *   file.h alloc_file_pseudo        pid.h change_pid
 *   proc_ns.h ns_get_path           path.h path_get
 *   fs_struct.h set_fs_pwd          syscalls.h ksys_unshare
 *   task_work.h task_work_add       seccomp.h seccomp_filter_release
 *   security.h security_*           ext4.h ext4_unregister_sysfs
 *   uaccess.h copy_*_nofault/strncpy_from_user_nofault
 *   jump_label.h static_key_count   cacheflush.h __flush_dcache_area
 *   fixmap.h __set_fixmap
 *   su_mount_ns.c（KernelSU 自带声明）path_mount / __arm64_sys_setns
 * ══════════════════════════════════════════════════════════════════════════ */

/* —— 凭据 / 身份 —— */
int commit_creds(struct cred *new)
{
    static int (*fn)(struct cred *);

    if (!fn) {
        fn = (int (*)(struct cred *))ksu_sym_ptr("commit_creds");
        if (!fn)
            return -ENOSYS;
    }
    return fn(new);
}

struct cred *prepare_creds(void)
{
    static struct cred *(*fn)(void);

    if (!fn) {
        fn = (struct cred *(*)(void))ksu_sym_ptr("prepare_creds");
        if (!fn)
            return NULL;
    }
    return fn();
}

const struct cred *override_creds(const struct cred *new)
{
    static const struct cred *(*fn)(const struct cred *);

    if (!fn) {
        fn = (const struct cred *(*)(const struct cred *))ksu_sym_ptr("override_creds");
        if (!fn)
            return NULL;
    }
    return fn(new);
}

void revert_creds(const struct cred *old)
{
    static void (*fn)(const struct cred *);

    if (!fn) {
        fn = (void (*)(const struct cred *))ksu_sym_ptr("revert_creds");
        if (!fn)
            return;
    }
    fn(old);
}

void abort_creds(struct cred *new)
{
    static void (*fn)(struct cred *);

    if (!fn) {
        fn = (void (*)(struct cred *))ksu_sym_ptr("abort_creds");
        if (!fn)
            return;
    }
    fn(new);
}

void set_groups(struct cred *new, struct group_info *group_info)
{
    static void (*fn)(struct cred *, struct group_info *);

    if (!fn) {
        fn = (void (*)(struct cred *, struct group_info *))ksu_sym_ptr("set_groups");
        if (!fn)
            return;
    }
    fn(new, group_info);
}

struct group_info *groups_alloc(int gidsetsize)
{
    static struct group_info *(*fn)(int);

    if (!fn) {
        fn = (struct group_info *(*)(int))ksu_sym_ptr("groups_alloc");
        if (!fn)
            return NULL;
    }
    return fn(gidsetsize);
}

void groups_free(struct group_info *group_info)
{
    static void (*fn)(struct group_info *);

    if (!fn) {
        fn = (void (*)(struct group_info *))ksu_sym_ptr("groups_free");
        if (!fn)
            return;
    }
    fn(group_info);
}

void groups_sort(struct group_info *group_info)
{
    static void (*fn)(struct group_info *);

    if (!fn) {
        fn = (void (*)(struct group_info *))ksu_sym_ptr("groups_sort");
        if (!fn)
            return;
    }
    fn(group_info);
}

struct user_struct *alloc_uid(kuid_t uid)
{
    static struct user_struct *(*fn)(kuid_t);

    if (!fn) {
        fn = (struct user_struct *(*)(kuid_t))ksu_sym_ptr("alloc_uid");
        if (!fn)
            return NULL;
    }
    return fn(uid);
}

/* —— kallsyms —— */
const char *kallsyms_lookup(unsigned long addr, unsigned long *symbolsize, unsigned long *offset,
                            char **modname, char *namebuf)
{
    static const char *(*fn)(unsigned long, unsigned long *, unsigned long *, char **, char *);

    if (!fn) {
        fn = (const char *(*)(unsigned long, unsigned long *, unsigned long *, char **, char *))ksu_sym_ptr("kallsyms_lookup");
        if (!fn)
            return NULL;
    }
    return fn(addr, symbolsize, offset, modname, namebuf);
}

unsigned long kallsyms_lookup_name(const char *name)
{
    static unsigned long (*fn)(const char *);

    if (!fn) {
        fn = (unsigned long (*)(const char *))ksu_sym_ptr("kallsyms_lookup_name");
        if (!fn)
            return 0;
    }
    return fn(name);
}

int kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize, unsigned long *offset)
{
    static int (*fn)(unsigned long, unsigned long *, unsigned long *);

    if (!fn) {
        fn = (int (*)(unsigned long, unsigned long *, unsigned long *))ksu_sym_ptr("kallsyms_lookup_size_offset");
        if (!fn)
            return 0;
    }
    return fn(addr, symbolsize, offset);
}

/* —— 命名空间 / 路径 —— */
long __arm64_sys_setns(const struct pt_regs *regs)
{
    static long (*fn)(const struct pt_regs *);

    if (!fn) {
        fn = (long (*)(const struct pt_regs *))ksu_sym_ptr("__arm64_sys_setns");
        if (!fn)
            return -ENOSYS;
    }
    return fn(regs);
}

int ksys_unshare(unsigned long unshare_flags)
{
    static int (*fn)(unsigned long);

    if (!fn) {
        fn = (int (*)(unsigned long))ksu_sym_ptr("ksys_unshare");
        if (!fn)
            return -ENOSYS;
    }
    return fn(unshare_flags);
}

int ns_get_path(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops)
{
    static int (*fn)(struct path *, struct task_struct *, const struct proc_ns_operations *);

    if (!fn) {
        fn = (int (*)(struct path *, struct task_struct *, const struct proc_ns_operations *))ksu_sym_ptr("ns_get_path");
        if (!fn)
            return -ENOSYS;
    }
    return fn(path, task, ns_ops);
}

void path_get(const struct path *path)
{
    static void (*fn)(const struct path *);

    if (!fn) {
        fn = (void (*)(const struct path *))ksu_sym_ptr("path_get");
        if (!fn)
            return;
    }
    fn(path);
}

int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page)
{
    static int (*fn)(const char *, struct path *, const char *, unsigned long, void *);

    if (!fn) {
        fn = (int (*)(const char *, struct path *, const char *, unsigned long, void *))ksu_sym_ptr("path_mount");
        if (!fn)
            return -ENOSYS;
    }
    return fn(dev_name, path, type_page, flags, data_page);
}

void set_fs_pwd(struct fs_struct *fs, const struct path *pwd)
{
    static void (*fn)(struct fs_struct *, const struct path *);

    if (!fn) {
        fn = (void (*)(struct fs_struct *, const struct path *))ksu_sym_ptr("set_fs_pwd");
        if (!fn)
            return;
    }
    fn(fs, pwd);
}

struct file *dentry_open(const struct path *path, int flags, const struct cred *cred)
{
    static struct file *(*fn)(const struct path *, int, const struct cred *);

    if (!fn) {
        fn = (struct file *(*)(const struct path *, int, const struct cred *))ksu_sym_ptr("dentry_open");
        if (!fn)
            return NULL;
    }
    return fn(path, flags, cred);
}

struct file *alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt, const char *name, int flags,
                               const struct file_operations *fops)
{
    static struct file *(*fn)(struct inode *, struct vfsmount *, const char *, int, const struct file_operations *);

    if (!fn) {
        fn = (struct file *(*)(struct inode *, struct vfsmount *, const char *, int, const struct file_operations *))
            ksu_sym_ptr("alloc_file_pseudo");
        if (!fn)
            return NULL;
    }
    return fn(inode, mnt, name, flags, fops);
}

int iterate_dir(struct file *file, struct dir_context *ctx)
{
    static int (*fn)(struct file *, struct dir_context *);

    if (!fn) {
        fn = (int (*)(struct file *, struct dir_context *))ksu_sym_ptr("iterate_dir");
        if (!fn)
            return -ENOSYS;
    }
    return fn(file, ctx);
}

/* —— 进程 / 任务 —— */
void change_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
    static void (*fn)(struct task_struct *, enum pid_type, struct pid *);

    if (!fn) {
        fn = (void (*)(struct task_struct *, enum pid_type, struct pid *))ksu_sym_ptr("change_pid");
        if (!fn)
            return;
    }
    fn(task, type, pid);
}

int task_work_add(struct task_struct *task, struct callback_head *twork, enum task_work_notify_mode mode)
{
    static int (*fn)(struct task_struct *, struct callback_head *, enum task_work_notify_mode);

    if (!fn) {
        fn = (int (*)(struct task_struct *, struct callback_head *, enum task_work_notify_mode))ksu_sym_ptr("task_work_add");
        if (!fn)
            return -ENOSYS;
    }
    return fn(task, twork, mode);
}

void seccomp_filter_release(struct task_struct *tsk)
{
    static void (*fn)(struct task_struct *);

    if (!fn) {
        fn = (void (*)(struct task_struct *))ksu_sym_ptr("seccomp_filter_release");
        if (!fn)
            return;
    }
    fn(tsk);
}

/* —— 内核内存 / 架构 —— */
void __flush_dcache_area(void *addr, size_t len)
{
    static void (*fn)(void *, size_t);

    if (!fn) {
        fn = (void (*)(void *, size_t))ksu_sym_ptr("__flush_dcache_area");
        if (!fn)
            return;
    }
    fn(addr, len);
}

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
    static void (*fn)(enum fixed_addresses, phys_addr_t, pgprot_t);

    if (!fn) {
        fn = (void (*)(enum fixed_addresses, phys_addr_t, pgprot_t))ksu_sym_ptr("__set_fixmap");
        if (!fn)
            return;
    }
    fn(idx, phys, prot);
}

/* —— 内核读写 —— */
ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
    static ssize_t (*fn)(struct file *, void *, size_t, loff_t *);

    if (!fn) {
        fn = (ssize_t (*)(struct file *, void *, size_t, loff_t *))ksu_sym_ptr("kernel_read");
        if (!fn)
            return -ENOSYS;
    }
    return fn(file, buf, count, pos);
}

ssize_t kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos)
{
    static ssize_t (*fn)(struct file *, const void *, size_t, loff_t *);

    if (!fn) {
        fn = (ssize_t (*)(struct file *, const void *, size_t, loff_t *))ksu_sym_ptr("kernel_write");
        if (!fn)
            return -ENOSYS;
    }
    return fn(file, buf, count, pos);
}

long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
    static long (*fn)(void *, const void __user *, size_t);

    if (!fn) {
        fn = (long (*)(void *, const void __user *, size_t))ksu_sym_ptr("copy_from_user_nofault");
        if (!fn)
            return -ENOSYS;
    }
    return fn(dst, src, size);
}

long notrace copy_to_user_nofault(void __user *dst, const void *src, size_t size)
{
    static long (*fn)(void __user *, const void *, size_t);

    if (!fn) {
        fn = (long (*)(void __user *, const void *, size_t))ksu_sym_ptr("copy_to_user_nofault");
        if (!fn)
            return -ENOSYS;
    }
    return fn(dst, src, size);
}

long notrace copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
    static long (*fn)(void *, const void *, size_t);

    if (!fn) {
        fn = (long (*)(void *, const void *, size_t))ksu_sym_ptr("copy_to_kernel_nofault");
        if (!fn)
            return -ENOSYS;
    }
    return fn(dst, src, size);
}

long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    static long (*fn)(char *, const void __user *, long);

    if (!fn) {
        fn = (long (*)(char *, const void __user *, long))ksu_sym_ptr("strncpy_from_user_nofault");
        if (!fn)
            return -ENOSYS;
    }
    return fn(dst, unsafe_addr, count);
}

/* —— LSM / SELinux —— */
int security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
    static int (*fn)(u32, char **, u32 *);

    if (!fn) {
        fn = (int (*)(u32, char **, u32 *))ksu_sym_ptr("security_secid_to_secctx");
        if (!fn)
            return -ENOSYS;
    }
    return fn(secid, secdata, seclen);
}

int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
    static int (*fn)(const char *, u32, u32 *);

    if (!fn) {
        fn = (int (*)(const char *, u32, u32 *))ksu_sym_ptr("security_secctx_to_secid");
        if (!fn)
            return -ENOSYS;
    }
    return fn(secdata, seclen, secid);
}

void security_release_secctx(char *secdata, u32 seclen)
{
    static void (*fn)(char *, u32);

    if (!fn) {
        fn = (void (*)(char *, u32))ksu_sym_ptr("security_release_secctx");
        if (!fn)
            return;
    }
    fn(secdata, seclen);
}

int security_inode_init_security_anon(struct inode *inode, const struct qstr *name, const struct inode *context_inode)
{
    static int (*fn)(struct inode *, const struct qstr *, const struct inode *);

    if (!fn) {
        fn = (int (*)(struct inode *, const struct qstr *, const struct inode *))ksu_sym_ptr("security_inode_init_security_anon");
        if (!fn)
            return -ENOSYS;
    }
    return fn(inode, name, context_inode);
}

/* —— 文件系统 —— */
void ext4_unregister_sysfs(struct super_block *sb)
{
    static void (*fn)(struct super_block *);

    if (!fn) {
        fn = (void (*)(struct super_block *))ksu_sym_ptr("ext4_unregister_sysfs");
        if (!fn)
            return;
    }
    fn(sb);
}

/* —— 静态键 —— */
int static_key_count(struct static_key *key)
{
    static int (*fn)(struct static_key *);

    if (!fn) {
        fn = (int (*)(struct static_key *))ksu_sym_ptr("static_key_count");
        if (!fn)
            return 0;
    }
    return fn(key);
}

/* ── path_umount：本颗内核头文件里没有声明（5.10 只有 may_umount），
 *    且宏会把 KernelSU 自己的声明搅坏 ⇒ 真转发定义，签名取自 KernelSU 声明。 */
int path_umount(struct path *path, int flags)
{
    static int (*fn)(struct path *, int);

    if (!fn) {
        fn = (int (*)(struct path *, int))ksu_sym_ptr("path_umount");
        if (!fn)
            return -ENOSYS;
    }
    return fn(path, flags);
}
EXPORT_SYMBOL(path_umount);