# 技术知识沉淀

## GhostLock 漏洞深度分析

### CVE-2026-43499 原理

`remove_waiter()` 函数在清除 PI 等待者时，错误地使用了 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`。在 proxy 路径中，`current` 是执行 requeue 操作的线程，而非原始 waiter，导致 waiter 的 `pi_blocked_on` 指针变成悬空指针。

### 触发条件

1. **CONFIG_FUTEX_PI=y** — 必须启用 FUTEX PI 支持
2. **3 个 futex words** — f_wait (waiter 等待), f_pi_target (PI 锁目标), f_pi_chain (PI 锁链)
3. **3 个线程** — waiter (等待), owner (持锁), consumer (requeue)
4. **精确时序** — FUTEX_CMP_REQUEUE_PI 必须在 waiter 真正阻塞后调用

### 影响范围

- Linux 2.6.39 到 7.1-rc1 (15 年的内核)
- Android 设备普遍受影响 (CONFIG_FUTEX_PI 默认启用)

## C ashmem vs Rust ashmem

### 类型混淆原理

C ashmem 的 `ashmem_area` 结构体中，`name[88]` 字段与 configfs 的 `configfs_buffer.bin_buffer` 指针在内存中重叠。通过 `ASHMEM_SET_NAME` 写入 name[88] 位置，可以控制 bin_buffer 指针，从而实现任意内核读写。

### 关键差异

| 特性 | C ashmem | Rust ashmem |
|------|----------|-------------|
| ashmem_area 大小 | 312 bytes | 不同 |
| name 字段偏移 | +0x00 (char[256]) | 不同布局 |
| name[88] 重叠 | ✅ 与 bin_buffer 重叠 | ❌ 不重叠 |
| GhostLock 利用 | ✅ 可行 | ❌ 不可行 |

### OPPO Find N2 验证

- 使用 `kmem_cache_create_usercopy` 创建 ashmem_area_cache (C 风格)
- 对象大小 312 字节
- UUID 路径 `/dev/ashmem874642ac-...` 可访问

## 帧大小验证方法

### IDA 验证流程

1. 打开 IDA，加载 output.elf (boot_unpacked)
2. 搜索目标函数 (如 `__arm64_sys_futex`)
3. 反汇编函数开头，找到 `SUB SP, SP, #imm` 指令
4. 帧大小 = imm 值

### 关键帧大小 (已验证)

| 函数 | 帧大小 | 验证来源 |
|------|--------|----------|
| __arm64_sys_futex | 0x90 | IDA disasm |
| do_futex | 0x70 | IDA disasm |
| futex_wait_requeue_pi | 0x1A0 | IDA disasm |
| sys_pselect6 | 0xA0 | IDA disasm |
| core_sys_select | 0x1C0 | IDA disasm |
| do_select | 0x3C0 | IDA disasm (STP+0x60 + SUB+0x360) |

### 栈布局计算

```
Futex 链总深: 0x90 + 0x70 + 0x1A0 = 0x300 (768B)
Waiter 位置: 0x300 - 0x78 = 0x288 (648B) from stack_top

Pselect 链总深: 0xA0 + 0x1C0 + 0x3C0 = 0x620 (1568B)
fd_set 位置: stack_top - 0x1F8 (504B)
```

## KPTI 对时序侧信道的影响

### 问题

KPTI (Kernel Page-Table Isolation) 启用后:
- 用户态和内核态使用不同页表
- 每次系统调用需要切换页表
- 引入不可预测的时序抖动
- cntvct_el0 (24MHz) 精度不足 (每 tick 42ns, 需要 ~1ns)
- PMCCNTR_EL0 需要内核权限

### 影响

- KernelSnitch futex hash timing 失败
- Cache-based timing 攻击失败
- 所有基于时序的内核地址泄漏方法失败

## SLUB 分配器参数

### OPPO Find N2 参数

| 参数 | 值 | 计算方法 |
|------|-----|----------|
| MM_STRUCT_SZ | 0x3c0 (960B) | pahole: 952B + 8B cpu_bitmap |
| MM_ORDER | 3 | SLUB order 计算: 32KB slabs |
| objects_per_slab | 34 | 32768 / 960 = 34 |
| futex_hashsize | 2048 | 8 CPUs * 256 |

### SLUB order 计算

```
slab_size = PAGE_SIZE << MM_ORDER = 4096 << 3 = 32768 bytes
objects_per_slab = slab_size / object_size = 32768 / 960 = 34
```

## ashmem 设备访问

### SELinux 限制

- `/dev/ashmem` (类型 `ashmem_device`): shell 无权限
- `/dev/ashmem874642ac-...` (类型 `ashmem_libcutils_device`): shell 有权限

### 解决方案

使用 UUID 后缀路径访问 ashmem 设备:
```bash
ls /dev/ashmem*  # 找到可用的 UUID 路径
```

## NebuSec 参考资料

### 关键链接

- GhostLock writeup: https://nebusec.ai/research/ionstack-part-2/
- Android stack reclaim: 即将发布
- CyberMeowfia PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c
- vmlinux-to-elf: https://github.com/marin-m/vmlinux-to-elf
