# 🏆 WIN — matisse (Redmi K50 Pro / MT6983 / kernel 5.10.209): uid 0 + kernel SID + KernelSU loaded

**时间**：2026-10-03 16:20:20（CST）｜**轮次**：新弹药 `mt88` 的第 1 轮即达成
**结论**：`uid=0(root) context=u:r:ksu:s0` + `/proc/modules` 出现 `kernelsu ... Live` ✓
**关键**：设备**从未崩机、从未重启**（`boot=874cf104`，uptime 持续增长）✓

---

## 1. 最终判据（全部设备实测，无一处依赖叙述行）

```
$ adb shell "su -c id"
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0        ★

$ adb shell "grep -E '^(ksu|kernelsu)' /proc/modules"
kernelsu 200704 0 - Live 0x0000000000000000 (O)                  ★ Live

$ adb shell "cat /data/local/tmp/ksu_go.log"
=== ksu_go start Sat Oct  3 16:20:20 CST 2026 uid=0 ===          ★ 装载器以 root 运行
uname=5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661
getenforce=Permissive
KMI=android12-5.10
[*] policy fixup (best effort)
[*] load_policy rc=0                                             ★ SELinux 策略修补成功
[*] ksud late-load kmi=android12-5.10
[*] late-load rc=0                                               ★★ 官方装载器成功
[*] modules: 1
kernelsu 286720 1 - Loading 0x0000000000000000 (O+)
=== ksu_go done ===

$ adb shell "cat /proc/10149/status | grep -E '^(Name|Uid|CapEff)'"
Name:   sleep
Uid:    0       0       0       0                                ★ 持毒进程 = 真 root, 仍 park 中
CapEff: 000001ffffffffff

$ adb shell "ls -la /system/bin/su"
-rwxr-xr-x 1 root root 4892712 /system/bin/su                   ★ KSU 已安装 su

$ adb shell "pm list packages | grep -i kernel"
package:me.weishu.kernelsu                                       ★ 管理器 v3.3.0
```

## 2. 成功的完整因果链

```
R 轮: real_cred=init_cred  →  E5 轮: enforcing 清零(Permissive)
  →  C 轮(45s 窗口, 单发): task+0x780 cred=init_cred ⇒ 真 uid=0（gate 命中）
  →  ★gate 分支（手机 AI 的 ASK7 补丁）★
        system("/system/bin/sh /data/local/tmp/ksu_go.sh > /data/local/tmp/ksu_go.log 2>&1 &")
     实测打印: mt47: after setres uid=0 euid=0 gid=0 egid=0
               mt47: ksud loader launched (uid=0) pid=10149
  →  ksu_go.sh: uid=0 → policy 第23字节 |0xC0 + load_policy(rc=0)
               → ksud late-load --kmi android12-5.10 --allow-shell (rc=0)
  →  /proc/modules: kernelsu Live   ⇒  su 就位  ⇒  uid=0(root) u:r:ksu:s0
  →  ★mt88 HOLD★: 持毒进程 park forever（不 _exit/unmap/teardown）⇒ 全程无 panic
```

## 3. 今天跨过的四个硬坑（每个都有实测根因）

| # | 坑 | 根因（实测） | 解法 |
|---|---|---|---|
| 1 | **装模块永远失败** | 预开 KO fd 被 prep 的克隆/管道 churn 掉 ⇒ `finit_module(3)`=EBADF(9)；门槛重开 ⇒ EACCES/ENOENT | 改用 **gate 里以 root 跑 `ksud late-load`**（官方 userspace 装载器，自带策略修补）|
| 2 | **exec 时机错** | 补丁打在 mt28g 的 `system()`（R 阶段）⇒ `ksu_go.log` 写着 `uid=2000` ⇒ abort ✗ | 插到 **mt47 gate**（真 uid=0 处）✓ |
| 3 | **C 崩机 6/8** | 持毒进程 `_exit(42)` ⇒ mm teardown ⇒ `lock_page_memcg` / `do_exit` panic | **`PSELECT_HOLD=1`**（6 个退出点永久 park）|
| 4 | **HOLD 后新崩法** | `Kernel panic - not syncing: Attempted to kill init!`—— C 落地后进程 cred=`init_cred`，**任何 SIGKILL 都等同杀 init** | 拔掉**所有** kill 路径：`cleangate` 的 `pkill -9 -x sleep`、C 阶段清理的 `pkill`、`kill "$cpid"`、`timeout 250`（→86400），封装里的 `pkill preload/sleep` |

## 4. 关键工程量（谁做了什么）
- **手机 AI**（Termux，源码在手）：
  - ASK6：把 `system("sh ksu_go.sh &")` **插到 mt47 gate**，重编出 `preload.so`（sha `1d987f4b`），并**证明可复现**（未打补丁重编 == 旧版 `dad14e77` 字节一致）
  - ASK8：定位 C 崩机主因（持毒进程自退）⇒ 交付 **mt88**（sha `390597469145a735`，`PSELECT_HOLD` + KO fd 重开修复）
- **本机侧**：45s C 窗口 / R 20s 安全阀 / 退场 285s / 崩前抢 pstore（单槽缓冲，`ls` 必被拒 ⇒ 按名直读）/ 尸检脚本 / 每轮现场与标记归档 / 连抽驱动（达成即停）
- **纪律**：未经同意不开火；落地后只读；任何 `adb.exe:/no devices` 整轮作废 ✓

## 5. 证据归档
- `logs_raw/WIN_1620_KSU/`：`R1.out`(886KB) `C1.out`(870KB) `E5a.out`(884KB) `ksu_go.log` `mt49_child_status.txt` `proc_modules_kernelsu.txt`
- `logs_raw/pstore/`：今天 6+ 份 panic 现场（含 `lock_page_memcg` / `rt_mutex_adjust_prio_chain` / `do_exit` / `Attempted to kill init`）
- `logs_raw/WIN_1142_LOGS/`、`logs_raw/WIN_1220_KEEP/`：两次早期 C 落地现场

## 6. 重启持久化（未完成，下一步）
KSU 的 **LKM late-load 是"每 boot 一次"** ⇒ 硬重启后模块丢失（`su` 也会消失）✗。
可选路线：
1. **重跑本流程**（recipe 已固化，且今天证明一轮可达：`tools/win_loop.sh`）✓ 最稳
2. 用当前 root **做一次 KSU 侧持久化配置**（例如让 ksud 的 late-load 在 boot 阶段被触发；需 root 与 `/data/adb` 权限）—— 待与手机 AI 讨论
3. 刷入修补过的 boot（需 BL 解锁 ✗ 用户已排除）
