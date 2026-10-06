/* ksu_syms_compat.c — 用 kprobe 拿到 kallsyms_lookup_name，再解析 49 个未导出符号
 * 为什么用 kprobe：register_kprobe() 在【内核内部】按名字查找符号 ⇒ 不受 EXPORT_SYMBOL
 * 限制 ⇒ 连 kallsyms_lookup_name 这种已被移除导出的符号也能拿到（non-GKI 标准技巧）。
 */
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/path.h>
#include "ksu_syms_compat.h"

typedef unsigned long (*ksu_kln_t)(const char *);

static ksu_kln_t g_kln;

/* 只做一次；失败也不致命（后面每次查找都会重试一次） */
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
    return (void *)addr;
}
EXPORT_SYMBOL(ksu_sym_ptr);

/* ── ★ 真转发定义：给“内核头文件里没有声明”的符号用 ──────────────────────
 * 为什么不能也用宏：宏会在【声明处】展开 ⇒ "expected identifier or '('"（CI 实测）。
 * 这里按 KernelSU 自己的声明写同名定义 ⇒ 声明照旧、链接由运行时解析补齐 ✓
 */
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
