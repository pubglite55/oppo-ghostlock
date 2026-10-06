/* ksu_syms_compat.h — non-GKI 符号运行时解析（强制包含头）
 * ────────────────────────────────────────────────────────────────────────────
 * 为什么需要它：厂商 SM8475 内核不 EXPORT KernelSU 用到的 44 个核心符号
 * （commit_creds / prepare_creds / kallsyms_lookup_name / path_mount / init_mm …），
 * 而且开着 CONFIG_TRIM_UNUSED_KSYMS=y ⇒ 模块硬链接它们 ⇒ finit_module 返回 -ENOENT，
 * 内核打印 "kernelsu: Unknown symbol <名> (err -2)"（实测已见）。
 *
 * 但设备内核同时具备：
 *   CONFIG_KPROBES=y  +  CONFIG_KALLSYMS_ALL=y  +  /proc/kallsyms 651630 行
 * ⇒ 这些符号【都存在，只是没导出】⇒ 可在运行时解析（non-GKI 的标准做法）。
 *
 * ★ 为什么不再用 #define X KSU_SYM(X) 宏路线（CI 连挂 3 次）：
 *   对象宏会在【声明处】也展开。KernelSU 强制包含本头，而内核的声明可能在
 *   本头之后才被解析 ⇒ 声明被搅成 "expected identifier or '('"：
 *     · asm/cacheflush.h:66  __flush_dcache_area（宏展开命中声明）
 *     · include/trace/events/syscalls.h:18  __tracepoint_sys_enter
 *       —— 它由 TRACE_EVENT_FN→DECLARE_TRACE→__DECLARE_TRACE 的
 *          __tracepoint_##name【token pasting】生成；粘贴结果会被再扫描并命中宏，
 *          连“先包含声明头”都救不了 ⇒ 宏对数据符号彻底不可行。
 *
 * ★ 现在的路线（真转发定义）：
 *   · 【函数符号】在 ksu_syms_compat.c 里写【同名】转发定义（首次调用用
 *     ksu_sym_ptr("名字") 解析并存进 static 函数指针）⇒ 模块内部自解析，
 *     内核侧不再有未定义引用 ⇒ finit_module 不再 ENOENT。签名全部取自
 *     【内核源码树里的真实原型】（grep include/ 得到），保证 CFI 类型哈希一致。
 *   · 【数据符号】是对象、不能用同名转发定义（身份/可变性要求它们就是内核那一个）：
 *       - init_mm / mntns_operations / selinux_state → 不同名访问器 ksu_get_*(),
 *         由 build-lkm.sh 在【少数使用点】改写源码调用访问器；
 *       - selinux_blob_sizes → 同名对象 + 首次解析时从内核对象 memcpy 一次
 *         （lsm_blob_sizes 在启动后不再变化，值拷贝是正确的）；
 *       - __tracepoint_sys_enter → 提供注册/注销助手 ksu_tp_*_sys_enter()，
 *         同样由 build-lkm.sh 改写 syscall_hook_manager.c 的两个调用点。
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
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/irqflags.h>
#include <linux/kthread.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/tracepoint.h>
#include <linux/jump_label.h>
#include <linux/uidgid.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/fdtable.h>

/* ── 运行期解析器本体：按名字查 kallsyms（未导出符号也能拿到）────────────── */
void *ksu_sym_ptr(const char *name);

/* ── 数据符号访问器（不同名）───────────────────────────────────────────────
 * 这几个是【对象】而非函数，内核头用 extern 声明它们，且
 *   · init_mm   —— 代码要拿它的【真实地址】走页表（phys_from_virt）
 *   · mntns_operations —— ns_get_path() 传的是它的地址，身份必须与内核一致
 *   · selinux_state    —— setenforce/getenforce 必须改到内核那一个对象
 * 因此不能同名转发，只能在少数使用点改用访问器。
 * 这里的 struct 都用【前置声明】即可（只用到指针）。 */
struct mm_struct;
struct selinux_state;
struct proc_ns_operations;
struct pt_regs;
struct tracepoint;

struct mm_struct *ksu_get_init_mm(void);
const struct proc_ns_operations *ksu_get_mntns_operations(void);
struct selinux_state *ksu_get_selinux_state(void);

/* ── __tracepoint_sys_enter 的注册/注销助手 ────────────────────────────────
 * __tracepoint_sys_enter 是 struct tracepoint 对象；它在 DECLARE_TRACE() 里被
 * __tracepoint_##name 的 token-pasting 引用 ⇒ 宏无法安全改写（CI 实测），
 * 只能在 syscall_hook_manager.c 的两个调用点改用这两个助手。
 * probe 签名与内核 register_trace_prio_sys_enter 的 data_proto 一致。 */
int ksu_tp_register_sys_enter(void (*probe)(void *, struct pt_regs *, long));
int ksu_tp_unregister_sys_enter(void (*probe)(void *, struct pt_regs *, long));

/* ── path_umount：本颗内核头文件里没有声明（5.10 只有 may_umount）───────
 * 不能 typeof()、宏又会搅坏 KernelSU 自己的声明 ⇒ 在 .c 里写【真转发定义】，
 * 签名取自 KernelSU 自己的声明。 */
int path_umount(struct path *path, int flags);

#endif /* _KSU_SYMS_COMPAT_H */