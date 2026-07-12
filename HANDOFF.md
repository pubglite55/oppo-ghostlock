# GhostLock OPPO Find N2 Exploit — Session Handoff

**Date**: 2026-07-13 (Updated)
**Device**: OPPO Find N2 (SM8475/CPH2413), Android 16, Kernel 5.10.236
**Project**: https://github.com/pubglite55/oppo-ghostlock/

---

## 1. Executive Summary

GhostLock (CVE-2026-43499) exploit chain targeting OPPO Find N2 is **stalled at mm_struct leak**:

- **KernelSnitch timing 根因已确认**: `FUTEX_WAKE_PRIVATE` val=0 在 kernel 5.10 上不遍历 hash chain
- **所有 futex timing 方法失败**: ratio 1.0-1.7x，远低于 10x 阈值
- **pselect side-channel 无法替代**: 泄漏内核栈数据 (nfulnl_logger)，非 mm_struct

### Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| 偏移验证 | ✅ 完成 | vmlinux objdump + IDA 双重验证 |
| MM_STRUCT_SZ / MM_ORDER | ✅ 已确认 | 0x500 / 3 (CyberMeowfia 验证) |
| futex_hashsize | ✅ 已修复 | 2048 (8 CPUs * 256) |
| KernelSnitch 碰撞查找 | ✅ 工作 | 找到 3 个碰撞 |
| **KernelSnitch mm_struct 泄漏** | ❌ **阻塞** | **FUTEX_WAKE_PRIVATE 不遍历 hash chain** |
| GhostLock FUTEX PI 触发 | ✅ 工作 | FUTEX_CMP_REQUEUE_PI ret=1 |
| **KASLR bypass (slide)** | ✅ 工作 | pselect side-channel 泄漏 nfulnl_logger |
| **mm_struct → kernel page** | ❌ **阻塞** | 依赖 mm_struct 地址 |
| pipe 物理读写 | ⏳ 待测 | 依赖 kernel page |
| 提权 (cred + SELinux) | ⏳ 待测 | 依赖 pipe physrw |

### 核心阻塞问题

**KernelSnitch timing 在 kernel 5.10 上完全失效**:

| 方法 | Timing Ratio | 需要阈值 | 结果 |
|------|-------------|---------|------|
| FUTEX_WAKE_PRIVATE val=0 | **1.0-1.5x** | >10x | ❌ 不遍历 hash chain |
| FUTEX_CMP_REQUEUE_PI | **1.4x** | >10x | ❌ 不够 |
| FUTEX_TRYLOCK_PI | **1.7x** | >10x | ❌ 不够 |

**根因**: Kernel 5.10 优化了 `FUTEX_WAKE_PRIVATE` with `val=0`，直接返回不遍历链表。

**pselect side-channel 无法替代 KernelSnitch**:
- pselect 泄漏的是内核栈数据 (nfulnl_logger 地址)，用于 KASLR bypass
- mm_struct 在 slab 分配器中，不在内核栈上
- pselect 泄漏的数据中不包含 current->mm 指针

---

## 2. 偏移验证结果 (vmlinux Verified)

### 帧大小 (IDA output.elf 验证, 2026-07-12)

| 函数 | 帧大小 | 来源 |
|------|--------|------|
| __arm64_sys_futex | 0x90 (144B) | SUB SP,SP,#0x90 |
| do_futex | 0x70 (112B) | SUB SP,SP,#0x70 |
| futex_wait_requeue_pi | 0x1a0 (416B) | SUB SP,SP,#0x1a0 |
| **总 futex 链** | **0x300 (768B)** | |
| **waiter 距栈顶** | **0x288 (648B)** | 0x300 - 0x78 |

### ⚠️ 重要: 之前的帧大小是错误的

| 函数 | 仓库旧值 | IDA 实际值 | 差异 |
|------|---------|-----------|------|
| sys_futex | 0x70 (112B) | 0x90 (144B) | +32B |
| do_futex | 0x130 (304B) | 0x70 (112B) | -192B |
| 总链 | 0x340 (832B) | 0x300 (768B) | -64B |
| waiter 位置 | stack_top-0x2c8 | stack_top-0x288 | +0x40 |

### SLUB 分配器参数

| 参数 | 值 | 来源 |
|------|-----|------|
| MM_STRUCT_SZ | 0x500 (1280B) | CyberMeowfia 验证 |
| MM_ORDER | 3 | SLUB order 计算: 32KB slabs |
| futex_hashsize | 2048 | 8 CPUs * 256 |

### 内核符号偏移 (IDA verified)

| 符号 | 偏移 | 地址 |
|------|------|------|
| ASHMEM_MISC_FOPS | 0x022c0048 | 0xffffffc00a2c0048 |
| INIT_TASK | 0x027cc000 | 0xffffffc00a7cc000 |
| ANON_PIPE_BUF_OPS | 0x0216aa68 | 0xffffffc00a16aa68 |
| NFULNL_LOGGER | 0x027c14b8 | 0xffffffc00a7c14b8 |
| SLIDE_RANDOM_BOOT_ID_DATA | 0x02b99acd | 0xffffffc00ab99acd |

### 关键函数地址 (IDA)

| 函数 | 地址 |
|------|------|
| `__arm64_sys_futex` | 0xffffffc00829d164 |
| `do_futex` | 0xffffffc0082932cc |
| `futex_wait_requeue_pi` | 0xffffffc008297f78 |
| `__arm64_sys_pselect6` | 0xffffffc008598c48 |
| `core_sys_select` | 0xffffffc0085976dc |
| `do_select` | 0xffffffc008597e2c |
| `binder_ioctl` | 0xffffffc009228e9c |
| `__sys_sendmsg` | 0xffffffc0093086d0 |

---

## 3. 测试结果汇总

### KernelSnitch timing 测试 (2026-07-13)

```
FUTEX_WAKE_PRIVATE val=0:
  Baseline (no waiters): 260 ns
  With 4096 waiters: 260 ns (ratio: 1.0x)  ← 完全没有差异!

FUTEX_CMP_REQUEUE_PI:
  Baseline: 625 ns
  With PI pile-up: 859 ns (ratio: 1.4x)  ← 不够

FUTEX_TRYLOCK_PI:
  Baseline: 520 ns
  With pile-up: 865 ns (ratio: 1.7x)  ← 不够
```

**结论**: Kernel 5.10 的 `FUTEX_WAKE_PRIVATE` with val=0 被优化为直接返回，不遍历 hash chain。所有基于 futex timing 的碰撞检测完全失效。

### 已测试的其他方法

| 方法 | 结果 | 原因 |
|------|------|------|
| Cache-based 时序 | ❌ 失败 | cntvct_el0 精度不足 (24MHz) |
| 辅助向量泄漏 | ❌ 失败 | 无内核地址 |
| /proc/kallsyms | ❌ 失败 | kptr_restrict 启用 |
| /proc/self/pagemap | ❌ 失败 | 全零 |
| ASHMEM | ❌ 失败 | SELinux |
| userfaultfd | ❌ 失败 | seccomp |
| perf_event_open | ❌ 失败 | SELinux |
| binder ioctl | ❌ 失败 | EACCES (shell 用户) |
| pselect side-channel | ✅ KASLR bypass | 泄漏 nfulnl_logger |
| **pselect → mm_struct** | ❌ **无法直接替代** | 泄漏内核栈数据，非 slab 数据 |

---

## 4. 文件与位置

### 本地机器 (macOS)
```
/Users/xiuxiu391/Desktop/oppo/
├── oppo-ghostlock/                    — 项目仓库
│   ├── exploit/
│   │   ├── Makefile                   — 构建脚本
│   │   ├── src/
│   │   │   ├── main.c                 — 主入口
│   │   │   ├── util.c                 — KernelSnitch 设置
│   │   │   ├── slide.c                — KASLR bypass (pselect)
│   │   │   ├── fops.c                 — file_operations 利用
│   │   │   ├── pipe.c                 — pipe 物理读写
│   │   │   ├── root.c                 — root 提权
│   │   │   ├── preload.c              — LD_PRELOAD 入口
│   │   │   ├── common.h               — 公共定义
│   │   │   └── kernelsnitch/          — KernelSnitch 库
│   │   ├── targets/oppo-find_n2/      — 设备特定配置
│   │   │   └── target.h               — 内核偏移量
│   │   └── test-programs/             — 测试程序
│   └── docs/                          — 文档
├── boot.img                           — 原始 boot 镜像 (192MB)
├── kernel_raw.bin                     — 提取的内核二进制
└── kernel.elf                         — vmlinux-to-elf 生成的 ELF
```

---

## 5. 编译与部署

### 编译
```bash
cd exploit/
make                    # 自动检测 NDK
make NDK=/path/to/ndk  # 指定 NDK 路径
```

### 部署
```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

---

## 6. 关键技术细节

### GhostLock 漏洞 (CVE-2026-43499)
- `remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`
- 影响 Linux 2.6.39 到 7.1，需要 CONFIG_FUTEX_PI=y
- 触发: 3 futex words + 3 threads → PI 依赖循环 → -EDEADLK → 错误回滚

### Kernel 5.10 FUTEX_WAKE_PRIVATE 优化

Kernel 5.10 对 `FUTEX_WAKE_PRIVATE` with `val=0` 进行了优化：
- 不遍历 futex hash chain
- 直接返回 0
- 导致 KernelSnitch 的 timing-based 碰撞检测完全失效

诊断测试验证：
```
4096 threads sleeping on same futex:
  FUTEX_WAKE_PRIVATE val=0: ratio 1.0x  ← 不遍历
  FUTEX_CMP_REQUEUE_PI:    ratio 1.4x  ← 不够
  FUTEX_TRYLOCK_PI:        ratio 1.7x  ← 不够
```

### pselect side-channel 限制

pselect side-channel 泄漏的是内核栈数据，不是 slab 数据：
- 泄漏的数据: nfulnl_logger 地址 (用于 KASLR bypass)
- mm_struct 在 slab 分配器中，不在内核栈上
- 无法直接从 pselect 泄漏推导出 mm_struct 地址

---

## 7. 下一步计划

### 优先级 1: 寻找替代 mm_struct 泄露方法

KernelSnitch timing 在 kernel 5.10 上完全失效，需要：
1. 研究 kernel 5.10 特定的内核信息泄露接口
2. 考虑 io_uring sq polling 泄漏内核地址
3. 研究是否可以利用其他 slab 对象泄漏

### 优先级 2: 利用已有 KASLR bypass

pselect side-channel 已经可以泄漏 KASLR base，可以：
1. 用 KASLR base 计算已知内核符号地址
2. 研究如何利用这些地址找到 mm_struct

### 优先级 3: 完成 Exploit 链

mm_struct 泄露完成后:
1. pipe.c — pipe buffer 物理读写
2. fops.c — 伪造 fops, CFI bypass
3. root.c — 提权 (patch cred + SELinux)

---

## 8. NebuSec 参考资料

官方 GhostLock writeup: https://nebusec.ai/research/ionstack-part-2/

关键要点:
- x86 Linux: 使用 PR_SET_MM_MAP 回收栈帧 (Android 上被 EPERM)
- 使用 prefetch 进行 KASLR 泄漏 (KPTI 关闭，但我们的设备 KPTI 启用)
- 使用 CEA (CPU Entry Area) 在已知地址放置可控内存 (x86 专用，ARM64 没有)
- PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c

K80U PR 参考: https://github.com/NebuSec/CyberMeowfia/pull/22
- 专家 Dere3046 建议: 使用 KernelSnitch，参考 K80U PR
- C ashmem 更简单路径: "c ashmem更简单 最终应该只需要适配部分就可以复现"

---

## 9. 设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **USB**: Connected via adb
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build fingerprint**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_NR_CPUS=32**, possible=0-7, online=8
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)
- **perf_event_paranoid=-1** (但 SELinux 仍阻止)

---

## 10. 测试程序

| 程序 | 用途 |
|------|------|
| test_futex.c | FUTEX PI 操作测试 |
| test_binder.c | binder ioctl 测试 |
| test_pselect_nfds.c | pselect NFDS 测试 |
| test_reclaim.c | stack reclaim 方法测试 |
| test_seccomp_futex.c | seccomp + futex 测试 |
| test_stamp.c | NebuSec PoC stamp 方法测试 |
| test_leak_mm.c | mm_struct 泄漏方法测试 |
| test_kernel_leak.c | 内核信息泄漏测试 |
| test_cache_timing.c | Cache-based 时序攻击测试 |
| test_improved_timing.c | 改进时序测量测试 |
| test_auxv_leak.c | 辅助向量泄漏测试 |

---

## 11. IDA 逆向分析结果 (2026-07-12)

**Binary**: output.elf (boot_unpacked), Image Base: 0xffffffc008000000

### 帧大小修正 (IDA verified)

| 函数 | 仓库旧值 | IDA 实际值 | 来源 |
|------|---------|-----------|------|
| `__arm64_sys_futex` | 0x70 | **0x90** | `SUB SP,SP,#0x90` |
| `do_futex` | 0x130 | **0x70** | `SUB SP,SP,#0x70` |
| `futex_wait_requeue_pi` | 0x1A0 | 0x1A0 | ✓ |
| `__arm64_sys_pselect6` | 0x90 | **0xA0** | `SUB SP,SP,#0xA0` |
| `core_sys_select` | 0x1D0 | **0x1C0** | `SUB SP,SP,#0x1C0` |
| `do_select` | 0x390 | **0x3C0** | `STP+0x60` + `SUB+0x360` |
| `binder_ioctl` | 0xF0 | **0xD0** | `SUB SP,SP,#0xD0` |
| `__sys_sendmsg` | ? | **0x314** | `SUB SP,SP,#0x314` |

### rt_mutex_waiter 在栈中的位置

从 `futex_wait_requeue_pi` 反编译验证：

```
waiter 结构体 = stack_top - 0x300 (帧底部)
waiter.lock = stack_top - 0x2C8 (关键字段)
```

| 字段 | 偏移 | 地址 |
|------|------|------|
| tree_entry | +0x00 | stack_top - 0x300 |
| pi_tree_entry | +0x18 | stack_top - 0x2E8 |
| task | +0x30 | stack_top - 0x2D0 |
| **lock** | **+0x38** | **stack_top - 0x2C8** |
| prio | +0x40 | stack_top - 0x2C0 |
| deadline | +0x48 | stack_top - 0x2B8 |

### 核心阻塞总结

1. **KernelSnitch timing 在 kernel 5.10 上完全失效** — FUTEX_WAKE_PRIVATE val=0 不遍历 hash chain
2. **所有 futex timing 方法失败** — ratio 1.0-1.7x，远低于 10x 阈值
3. **pselect side-channel 无法替代 KernelSnitch** — 泄漏内核栈数据，非 slab 数据
4. **需要寻找替代 mm_struct 泄露方法** — 这是当前唯一阻塞点

### 下一步: 替代 mm_struct 泄露方法

需要研究 kernel 5.10 特定的内核信息泄露接口，可能的方向：
1. io_uring sq polling 泄漏内核地址
2. 研究其他 slab 对象泄漏
3. 利用已有 KASLR bypass 推导 mm_struct
