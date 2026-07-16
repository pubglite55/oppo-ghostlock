# docs/architecture.md

# 架构设计文档

## 设计理念

本项目的核心设计目标是将 x86_64 平台的 GhostLock exploit 适配到 ARM64 架构的 OPPO Find N2 设备。整体架构遵循分层设计原则：

1. **最小权限原则** — 在无 root 环境下尽可能利用内核漏洞
2. **模块化设计** — 每个利用阶段独立实现，便于调试和替换
3. **IDA 驱动开发** — 所有内核偏移通过 IDA Pro 验证，不信任仓库默认值

## 整体架构

<!-- 架构图占位 -->

```
┌─────────────────────────────────────────────────────────┐
│                    Exploit Chain                         │
├─────────────┬─────────────┬─────────────┬───────────────┤
│  Stage 1    │  Stage 2    │  Stage 3    │  Stage 4      │
│  Firefox    │  KASLR      │  GhostLock  │  Root         │
│  CVE-2026   │  Bypass     │  Trigger    │  Escalation   │
│  -10702     │  (KernelSnitch) │         │               │
├─────────────┼─────────────┼─────────────┼───────────────┤
│  SpiderMonkey│  futex hash │  FUTEX_CMP  │  cred patch   │
│  type confu-│  timing     │  _REQUEUE_PI│  init_cred    │
│  sion → AAW │  → mm_struct│  → rtmutex  │  → uid=0      │
└─────────────┴─────────────┴─────────────┴───────────────┘
```

### 分层职责

| 层级 | 组件 | 核心作用 |
|------|------|----------|
| Stage 1 | Firefox CVE-2026-10702 | 浏览器端代码执行，加载 preload.so |
| Stage 2 | KernelSnitch | 泄漏 mm_struct 内核地址 |
| Stage 3 | GhostLock trigger | 创建悬空 pi_blocked_on 指针 |
| Stage 4 | pipe physrw / root | 物理读写 → cred 覆写 → root |
| 工具层 | IDA Pro MCP | 内核偏移验证与反编译 |

## 核心模块详解

### KernelSnitch (mm_struct 泄漏)

**功能定位**: 通过 futex hash timing 泄漏当前进程的 mm_struct 内核地址。

**实现原理**:
1. 使用 `futex()` 系统调用的 hash table 冲突检测
2. 当多个线程竞争同一个 futex key 时，内核会将它们放入同一个 hash bucket
3. 通过测量 `futex_wake` 的时序差异，可以推断 hash bucket 的内容
4. mm_struct 作为 futex key 的一部分，其地址会反映在时序中

**关键参数 (OPPO PGU110)**:
- `MM_STRUCT_SZ = 0x3c0` (960 bytes)
- `MM_ORDER = 3` (32KB slabs)
- `KSNITCH_COLLISIONS = 16`
- `futex_hashsize = 2048`

**7-bug 修复**:
1. IDENTITY range: `0xffffff80-0xffffffc0` (直接映射区)
2. KSNITCH_COLLISIONS: 4 → 16
3. MM_STRUCT_SZ: 0x500 → 0x3c0
4. hashsize 对齐: `roundup_pow2(nr_cpu_ids * 256)`
5. pile-up 验证: yield 16 次
6. futex_hash_table_size: 使用 `futex_hashsize`
7. nr_cpu_ids: 读取 `/sys/devices/system/cpu/possible`

### GhostLock FUTEX 触发

**功能定位**: 通过 `FUTEX_CMP_REQUEUE_PI` 创建悬空的 `pi_blocked_on` 指针。

**实现原理**:
1. 创建 3 个线程: waiter / owner / consumer
2. waiter 调用 `FUTEX_WAIT_REQUEUE_PI` 等待
3. owner 调用 `FUTEX_CMP_REQUEUE_PI` � waiter 重新入队
4. 竞态条件下，waiter 的 `pi_blocked_on` 指针悬空

**关键偏移**:
- `task_struct->pi_blocked_on = 0x888`
- `rt_mutex_waiter->lock = 0x38`
- `rt_mutex_waiter->task = 0x30`

### pipe physrw (物理读写)

**功能定位**: 通过 pipe buffer 操作实现任意物理内存读写。

> [!NOTE] 待补充：pipe physrw 当前被 ashmem 无 configfs 支持阻塞

### pselect fd_set 栈覆盖

**功能定位**: 通过 pselect 的 fd_set 参数覆盖内核栈上的 waiter 结构。

**阻塞原因**: 
- NFDS > 336: fd_set 通过 `bitmap_alloc()` 分配在堆上
- NFDS ≤ 336: fd_set 在栈上，但 waiter 在 fd_set 下方 120 字节，无法覆盖

## 核心业务流程

### 利用链完整流程

```
1. Firefox CVE-2026-10702
   └── SpiderMonkey type confusion → AAW → mprotect GOT → shellcode
       └── execve("/system/bin/sh")

2. preload.so (LD_PRELOAD)
   └── 拦截系统调用，注入恶意逻辑
       └── 调用 KernelSnitch

3. KernelSnitch
   └── futex hash timing → mm_struct 地址泄漏
       └── 从 mm_struct->owner 计算 task_struct

4. GhostLock trigger
   └── FUTEX_CMP_REQUEUE_PI → rtmutex PI chain
       └── 创建悬空 pi_blocked_on 指针

5. sk_buff reclaim
   └── socketpair send → sk_buff 堆喷射
       └── 回收 freed 内存

6. pipe physrw (当前阻塞)
   └── configfs R/W → pipe buffer 修改
       └── 物理内存任意读写

7. root escalation (当前阻塞)
   └── init_task.tasks walk → cred patch
       └── uid=0, caps=FULL, SID=1
```

## 技术选型说明

### KernelSnitch vs pselect slide

| 维度 | KernelSnitch | pselect slide |
|------|-------------|---------------|
| 原理 | futex hash timing | fd_set 栈覆盖 |
| KASLR 依赖 | 不依赖 | 依赖 |
| UBSAN_TRAP 影响 | 无影响 | 触发 BRK panic |
| 适用性 | kernel 5.10+ | 仅 QEMU |
| 选择原因 | OPPO 内核有 UBSAN_TRAP | — |

### PR #13 bypass vs slide

| 维度 | PR #13 bypass | slide |
|------|--------------|-------|
| 原理 | 直接计算 kaslr_base | pselect 泄漏 |
| 可靠性 | 100% | 不稳定 (boot_id 破坏) |
| 复杂度 | 低 | 高 |
| 选择原因 | XBL 固件硬编码物理地址 | — |
