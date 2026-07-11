# GhostLock OPPO Find N2 Exploit — Session Handoff

**Date**: 2026-07-12 (Updated)  
**Device**: OPPO Find N2 (SM8475/CPH2413), Android 16, Kernel 5.10.236  
**Project**: https://github.com/pubglite55/oppo-ghostlock/

---

## 1. Executive Summary

GhostLock (CVE-2026-43499) exploit chain targeting OPPO Find N2 is **stalled at two critical points**:
1. **KernelSnitch mm_struct leak fails** — KPTI enabled, timing side-channel inaccurate
2. **KASLR bypass blocked** — No syscall writes user-controlled data at waiter position

### Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| 偏移验证 | ✅ 完成 | vmlinux objdump + pahole 双重验证 |
| MM_STRUCT_SZ / MM_ORDER | ✅ 已确认 | 0x3c0 / 3 (pahole 验证) |
| futex_hashsize | ✅ 已修复 | 2048 (8 CPUs * 256) |
| KernelSnitch 碰撞查找 | ✅ 工作 | 找到 3 个碰撞 |
| **KernelSnitch mm_struct 泄漏** | ❌ **阻塞** | **KPTI 导致时序不准确** |
| GhostLock FUTEX PI 触发 | ✅ 工作 | 3 futex words + 3 threads → -EDEADLK |
| **KASLR bypass (slide)** | ❌ **阻塞** | **无 syscall 在 waiter 位置写入用户可控数据** |
| pipe 物理读写 | ⏳ 待测 | 依赖 KASLR bypass |
| 提权 (cred + SELinux) | ⏳ 待测 | 依赖 pipe physrw |

### 核心阻塞问题

**问题 1: KernelSnitch mm_struct 泄漏失败**
- 原因: KPTI 启用 (`CONFIG_UNMAP_KERNEL_AT_EL0=y`)，cntvct_el0 精度不足 (24MHz)
- 影响: 无法获取 mm_struct 地址，后续 exploit 无法进行

**问题 2: waiter 位置无法到达**
- waiter 位置: `stack_top - 0x2c8` (712B)
- 已测试的所有 stack reclaim 方法均失败
- 差距: pselect fd_set 在 stack_top-0x1f8，差距 208B

---

## 2. 偏移验证结果 (vmlinux Verified)

### 帧大小 (OPPO 内核源码编译 vmlinux, objdump 验证)

| 函数 | 帧大小 | 来源 |
|------|--------|------|
| __arm64_sys_futex | 0x70 (112B) | SUB SP,SP,#0x70 |
| do_futex | 0x130 (304B) | SUB SP,SP,#0x130 |
| futex_wait_requeue_pi | 0x1a0 (416B) | SUB SP,SP,#0x1a0 |
| **总 futex 链** | **0x340 (832B)** | |
| **waiter 距栈顶** | **0x2c8 (712B)** | 0x340 - 0x78 |

### ⚠️ 重要: 之前的帧大小是错误的

| 函数 | 旧值 | 新值 | 差异 |
|------|------|------|------|
| sys_futex | 0x10 (16B) | 0x70 (112B) | +96B |
| do_futex | 0x1c0 (448B) | 0x130 (304B) | -144B |
| waiter 位置 | stack_top-0x358 | stack_top-0x2c8 | -144B |

### SLUB 分配器参数 (pahole 验证)

| 参数 | 值 | 验证方法 |
|------|-----|----------|
| MM_STRUCT_SZ | 0x3c0 (960B) | pahole: 952B + 8B cpu_bitmap |
| MM_ORDER | 3 | SLUB order 计算: 32KB slabs |
| objects_per_slab | 34 | 32768 / 960 = 34 |
| futex_hashsize | 2048 | 8 CPUs * 256 |

### pselect 链分析

| 函数 | 帧大小 |
|------|--------|
| sys_pselect6 | 0x90 (144B) |
| core_sys_select | 0x1d0 (464B) |
| do_select | 0x390 (912B) |
| **总计** | **0x610 (1552B)** |

- fd_set 位置: stack_top - 0x1f8 (504B)
- waiter 位置: stack_top - 0x2c8 (712B)
- **差距: 208B — fd_set 无法触及 waiter**

---

## 3. 测试结果汇总

### 已测试的方法

| 方法 | 结果 | 原因 |
|------|------|------|
| Cache-based 时序 | ❌ 失败 | cntvct_el0 精度不足 (24MHz, 每 tick 42ns) |
| 改进时序测量 | ❌ 失败 | 变异系数 106.95%，不稳定 |
| 辅助向量泄漏 | ❌ 失败 | 无内核地址，仅用户态地址 |
| PMCCNTR_EL0 | ❌ 失败 | 需要内核权限，用户态无法访问 |
| /proc/kallsyms | ❌ 失败 | kptr_restrict 启用，所有地址为 0 |
| /proc/self/pagemap | ❌ 失败 | 全零，内核限制物理页信息 |
| ASHMEM | ❌ 失败 | Permission denied (SELinux) |
| userfaultfd | ❌ 失败 | Operation not permitted (seccomp) |
| fork 时序 | ❌ 失败 | 精度太低 (1077μs/次) |

### KernelSnitch 碰撞查找

```
[*] KS: sz=0x3c0 order=3 cpu=8
[*] KS: ORDER3=0x8000 objs_per_slab=34
[*] parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (4) mte disabled
[*] futex_init: nprocs_conf=8 nprocs_onln=8 futex_hashsize=2048
[*] start finding collisisons
[*] found 3 collisisons
[*] start bruteforcing
[*] done
[-] KernelSnitch mm_struct leak failed
```

**结论**: 碰撞查找成功，但暴力搜索 64GB 地址空间未找到 mm_struct。

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
│   │   │   ├── slide.c                — KASLR bypass
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
└── kernel_raw.bin                     — 提取的内核二进制
```

### 服务器 (43.139.246.47)
```
~/android_kernel_oppo_sm8475-oppo-sm8475_b_16.0.0_find_n2/
    └── vmlinux                        — 编译的内核 (410MB, 有符号)
~/boot-new.img                         — 上传的 boot.img
~/kernel-from-boot.bin                 — 从 boot.img 提取的内核
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

### KPTI 对时序的影响

KPTI (Kernel Page-Table Isolation) 启用后:
- 用户态和内核态使用不同页表
- 每次系统调用需要切换页表
- 引入不可预测的时序抖动
- cntvct_el0 (24MHz) 精度不足，无法检测微小差异

### 为什么 PMCCNTR_EL0 无法使用

PMCCNTR_EL0 是 CPU 周期计数器，精度高 (GHz 级别)，但:
- 需要内核权限 (PMUSERENR_EL0)
- 用户态无法直接访问
- Android SELinux 阻止

---

## 7. 下一步计划

### 优先级 1: 等待 NebuSec Android blog

NebuSec 已确认将在下一篇 Android blog 中讨论:
- Android 上的 stack reclaim 方法
- ASLR bypass 技术
- CFI bypass 方法

来源: https://nebusec.ai/research/ionstack-part-2/

### 优先级 2: 如果 Stack Reclaim 找到

1. 实现到 slide.c
2. 编译并在设备上测试
3. 验证 boot_id 泄漏 (应该是内核基地址)

### 优先级 3: 完成 Exploit 链

KASLR bypass 完成后:
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
- 使用 inet6_protos[IPPROTO_UDP] 作为写入目标
- **他们明确表示**: "next blog will discuss how to exploit GhostLock on Android"
- PoC: https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/poc/poc.c

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
