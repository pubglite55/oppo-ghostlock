# 技术知识沉淀

> 状态（2026-10-05 冻结）：布局/结构/栈偏移数据仍为权威；`real_cred`/`cred` 偏移已按 `commit_creds` 反汇编更正为 `0x778`/`0x780`（见 [`docs/matisse-port.md`](matisse-port.md) §3.1）。

## OPPO Find N2 内核内存布局

### 地址空间布局

| 区域 | 地址范围 | 说明 |
|------|----------|------|
| 内核文本段 | `0xffffffc008000000` | KIMAGE_TEXT_BASE |
| 直接映射区 | `0xffffff8000000000 - 0xffffffc000000000` | 16GB, slab 分配所在 |
| 物理内存起始 | `0x80000000` | P0_PHYS_OFFSET |
| 内核物理加载地址 | `0xa8000000` | XBL 固件硬编码 |

### 地址转换公式

```c
// 内核镜像地址 → 直接映射地址
P0_DATA_ALIAS_CONST(addr) = P0_PAGE_OFFSET | ((addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA)

// P0_KERNEL_PHYS_DELTA = P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET = 0x28000000
```

### 常用直接映射地址

| 符号 | 内核镜像地址 | 直接映射地址 |
|------|-------------|-------------|
| init_task | `0xffffffc00a7cbf60` | `0xffffff802a7cbf60` |
| ashmem_fops | `0xffffffc00a2c0048` | `0xffffff802a2c0048` |
| random_boot_id | `0xffffffc00ab99b6d` | `0xffffff802ab99b6d` |
| nfulnl_logger | `0xffffffc00a7c14b8` | `0xffffff802a7c14b8` |

## task_struct 布局 (kernel 5.10.236)

### 关键字段偏移

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| pid | `0x618` | 4 | 进程 ID |
| tgid | `0x61c` | 4 | 线程组 ID |
| real_parent | `0x628` | 8 | 父进程 |
| real_cred | `0x778` | 8 | 真实 cred 指针（旧值 `0x818` 经 `commit_creds` 反汇编更正） |
| cred | `0x780` | 8 | 有效 cred 指针（旧值 `0x820` 经 `commit_creds` 反汇编更正） |
| comm | `0x830` | 16 | 进程名 |
| tasks | `0x550` | 16 | 任务链表 |
| seccomp | `0x8e8` | — | seccomp 状态 |

### PI 字段 (try_to_wake_up IDA VERIFIED)

| 字段 | 偏移 | 来源 |
|------|------|------|
| pi_lock | `0x86c` | `ADD X21, X20, #0x86C` |
| pi_waiters | `0x870` | 紧随 pi_lock |
| pi_top_task | `0x880` | 紧随 pi_waiters |
| pi_blocked_on | `0x888` | 紧随 pi_top_task |

> [!NOTE]
> 52pojie 文章 (kernel 6.6) 值为 `0x90c/0x920/0x930/0x898`，在 5.10.236 上偏差约 `-0xa0~-0xb0` 字节。

## rt_mutex_waiter 结构 (kernel 5.10.236)

### 字段偏移

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| tree_entry | `0x00` | 16 | rb_node |
| pi_tree_entry | `0x18` | 16 | rb_node |
| task | `0x30` | 8 | task_struct 指针 |
| lock | `0x38` | 8 | rt_mutex 指针 |
| prio | `0x40` | 4 | 优先级 |
| deadline | `0x48` | 8 | 截止时间 |
| **结构大小** | **0x50** | **80** | — |

> [!NOTE]
> 无 `wake_state` / `ww_ctx` 字段 (5.10.236 无此字段)。

## file_operations 偏移 (output.elf VERIFIED 2026-10-04)

> [!WARNING]
> 本 build 的 `struct file_operations` 与 mainline 5.10 **不同**:`unlocked_ioctl` 落在 `0x50`
> (mainline 为 `0x48`),自该字段起整体 **+8**。下表为 `output.elf` 实测值,与
> `exploit/targets/oppo-find_n2/target.h` 的 `FOPS_*_OFF` 一致。
> (此前本节的 `0x48/0x50/0x58/0x68/0x78/0xd8` 是**错的**,已更正。详见 `docs/offset-audit.md`。)

| 字段 | 偏移 | 说明 |
|------|------|------|
| owner | `0x00` | — |
| llseek | `0x08` | — |
| read | `0x10` | — |
| write | `0x18` | — |
| read_iter | `0x20` | — |
| write_iter | `0x28` | — |
| unlocked_ioctl | `0x50` | 旧值 0x48 已更正 |
| compat_ioctl | `0x58` | 旧值 0x50 已更正 |
| mmap | `0x60` | 旧值 0x58 已更正 |
| open | `0x70` | 旧值 0x68 已更正 |
| release | `0x80` | 旧值 0x78 已更正 |
| show_fdinfo | `0xe0` | 旧值 0xd8 已更正 |

### ashmem fops 表实测内容 (VA `0xffffffc00a2c0048`)

| 槽位 | 符号 |
|------|------|
| +0x08 llseek | `ashmem_llseek` (`0x011ee5d4`) |
| +0x20 read_iter | `ashmem_read_iter` (`0x011ee6ec`) |
| +0x50 unlocked_ioctl | `ashmem_ioctl` (`0x011ee7d0`) |
| +0x58 compat_ioctl | `compat_ashmem_ioctl` (`0x011ef2e0`) |
| +0x60 mmap | `ashmem_mmap` (`0x011ef340`) |
| +0x70 open | `ashmem_open` (`0x011ef580`) |
| +0x80 release | `ashmem_release` (`0x011ef620`) |
| +0xe0 show_fdinfo | `ashmem_show_fdinfo` (`0x011ef744`) |

## KernelSnitch 参数

| 参数 | 值 | 说明 |
|------|-----|------|
| MM_STRUCT_SZ | `0x3c0` | 960 bytes |
| MM_ORDER | `3` | 32KB slabs |
| KSNITCH_COLLISIONS | `16` | 碰撞检测次数 |
| MM_OWNER_OFF | `0x348` | mm_struct.owner_task 偏移 |
| futex_hashsize | `2048` | `roundup_pow2(nr_cpu_ids * 256)` |
| nr_cpu_ids | `8` | 读取 `/sys/devices/system/cpu/possible` |
| IDENTITY_START | `0xffffff8000000000` | 直接映射区起始 |
| IDENTITY_END | `0xffffffc000000000` | 直接映射区结束 |

## 内核栈布局 (pselect + futex)

### 栈帧大小 (IDA VERIFIED)

| 函数 | 帧大小 | 说明 |
|------|--------|------|
| `__arm64_sys_futex` | `0x90` | `SUB SP,SP,#0x90` |
| `do_futex` | `0x70` | `SUB SP,SP,#0x70` |
| `futex_wait_requeue_pi` | `0x1A0` | `SUB SP,SP,#0x1A0` |
| **futex chain 总计** | **0x300** | 768B |
| **waiter 距栈顶** | **0x270** | 624B (IDA VERIFIED 2026-07-14) |
| `__arm64_sys_pselect6` | `0xA0` | `SUB SP,SP,#0xA0` |
| `core_sys_select` | `0x1C0` | `SUB SP,SP,#0x1C0` |
| `do_select` | `0x3C0` | `STP+0x60 + SUB+0x360` |

### fd_set 与 waiter 偏移差 (IDA VERIFIED 2026-07-14)

```
fd_set 数据: stack_top - 0x210 (core_sys_select SP+0x50)
waiter: stack_top - 0x270 (futex_wait_requeue_pi SP+0x90)
偏移差: 0x60 (96 bytes)

注意: 之前 AGENTS.md 记录为 stack_top - 0x288 (120 bytes)，经 IDA 重新验证为 0x270 (96 bytes)
```

> [!WARNING]
> 之前的 repo 值是错误的 (sys_futex=0x70, do_futex=0x130, do_select=0x390)。必须使用 IDA 验证的值。

## CVE-2026-23274 IDLETIMER UAF

### 漏洞机制

- IDLETIMER target 创建 timer 结构体，包含 `function` 回调指针
- 通过 UAF + setxattr 喷射回收，控制 timer.function → ROP chain
- 原始 exploit 是 x86_64 (kernelCTF $10,500 bounty)

### OPPO 阻塞原因

```
没有 CAP_NET_RAW → 无法触发漏洞
├── CONFIG_USER_NS is not set → 无法 CLONE_NEWUSER
├── SELinux Enforcing → 阻止 BPF/ashmem/userfaultfd
└── CapEff=0x0 → 零 capabilities
```

### ARM64 ROP Gadgets

| Gadget | 地址 | 指令 |
|--------|------|------|
| LDR X8,[X0]; BLR X8 | `0xffffffc00a4a1670` | 从 X0 加载函数指针并调用 |
| MOV X0, XZR | `0xffffffc0080118e0` | 设置 X0=0 |
| MOV X0, X1; RET | `0xffffffc008020358` | 函数返回值传递 |
| MOV SP, X29; LDP... | `0xffffffc0080a2bc0` | stack pivot |
| RET | `0xffffffc008010108` | 函数返回 |
