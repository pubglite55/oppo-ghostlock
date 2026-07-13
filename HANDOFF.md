# GhostLock OPPO Find N2 Exploit — Session Handoff

**Date**: 2026-07-14 (Updated)
**Device**: OPPO Find N2 (SM8475/CPH2413), Android 16, Kernel 5.10.236
**Project**: https://github.com/pubglite55/oppo-ghostlock/

---

## 1. Executive Summary

GhostLock (CVE-2026-43499) exploit chain targeting OPPO Find N2 is **stalled at slide pselect (栈覆盖)**:

- **KernelSnitch 已完全修复**: pile-up ✅, hashsize ✅, IDENTITY range ✅, bruteforce ✅
- **slide pselect 不可行**: waiter 在 fd_set 数据下方 120 字节，fd_set bitmaps 无法到达 waiter 位置
- **PR #11 merged**: boot_id 数据偏移修正
- **PR #12 merged**: P0_PAGE_OFFSET 和 P0_KERNEL_PHYS_LOAD 修正

### Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| 偏移验证 | ✅ 完成 | vmlinux objdump + IDA 双重验证 |
| MM_STRUCT_SZ / MM_ORDER | ✅ 已确认 | 0x3c0 / 3 (pahole 验证) |
| futex_hashsize | ✅ 已修复 | 2048 (8 CPUs * 256) + roundup_pow_of_two |
| KernelSnitch pile-up 验证 | ✅ 已修复 | yield 16 次 + timing 测量 |
| KernelSnitch IDENTITY range | ✅ 已修复 | 0xffffff80-0xffffffc0 (direct-map) |
| KernelSnitch bruteforce | ✅ **成功** | mm_struct=0xffffff89807912c0 |
| KASLR bypass (slide) | ✅ 工作 | pselect side-channel 泄漏 nfulnl_logger |
| GhostLock FUTEX PI 触发 | ✅ 工作 | FUTEX_CMP_REQUEUE_PI ret=1 |
| sk_buff reclaim | ✅ 完成 | 4/4 send 成功 |
| **slide pselect (栈覆盖)** | ❌ **不可行** | waiter offset 120B — NOT VIABLE |
| configfs R/W | ❌ **死路** | ashmem strcpy 行为 |
| pipe physrw | ⏳ 待实现 | 依赖栈覆盖修复 |
| root (cred + SELinux) | ⏳ 待实现 | 依赖 pipe physrw |

---

## 2. 关键技术细节

### 2.1 KernelSnitch 修复 (已验证)

**修复清单**:
1. IDENTITY range: `0xffffffc0-ffffffc4` → `0xffffff80-ffffffc0`
2. KSNITCH_COLLISIONS: 4 → 16
3. MM_STRUCT_SZ: 0x500 → 0x3c0
4. hashsize alignment: 添加 `roundup_pow2`
5. pile-up verification: yield 16 次 + timing 测量

**设备验证结果**:
```
[*] parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (16)
[*] pile-up verified: approx_time=2673
[*] found 15 collisisons
[*] leaked_mm=ffffff89807912c0 base=ffffff8980790000
[*] sk_buff reclaim send 4/4 ret=65536 errno=0
```

### 2.2 slide pselect 根因分析

**问题**: waiter 偏移错位 120 字节

**精确偏移计算 (IDA 验证)**:
```
pselect 帧链: pselect6(0xA0) + core_sys_select(0x1C0) + do_select(0x3C0) = 0x620
core_sys_select SP = stack_top - 0x260
fd_set 数据 (v35) = SP + 0x50 = stack_top - 0x210
waiter 结构 = stack_top - 0x288
偏移差 = 0x288 - 0x210 = 0x78 (120 bytes)
```

**`FRONTEND_STACK_ALLOC=256`** 确认阈值为 42.67 bytes，NFDS=320 是栈路径最大值。没有 NFDS 值能让 fd_set 覆盖 waiter 位置。

### 2.3 configfs type confusion (死路)

**问题**: ashmem SET_NAME 使用 strcpy 行为，内核地址 LE 首字节为 NUL → page 地址无法写入

**结论**: 无解决方案，此路径已放弃。

---

## 3. 文件位置

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

## 4. 编译与部署

### 编译
```bash
cd exploit/
make NDK=/tmp/ndk_extract/android-ndk-r29
```

### 部署
```bash
adb push preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

---

## 5. 下一步计划

### 优先级 1: 修复 slide pselect

当前 slide 机制不可行 (waiter 在 fd_set 数据下方 120 字节)。需要:
1. 找到其他 syscall 将用户可控数据放置到 waiter 位置
2. 或重新设计 slide 机制

### 优先级 2: 完成 exploit 链

mm_struct 泄漏完成后:
1. pipe.c — pipe buffer 物理读写
2. fops.c — 伪造 fops, CFI bypass
3. root.c — 提权 (patch cred + SELinux)

---

## 6. 参考资料

- 官方 GhostLock writeup: https://nebusec.ai/research/ionstack-part-2/
- K80U PR #22: https://github.com/NebuSec/CyberMeowfia/pull/22
- Dere3046 专家建议: "c ashmem更简单 最终应该只需要适配部分就可以复现"

---

## 7. 设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **USB**: Connected via adb
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build fingerprint**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_NR_CPUS=32**, possible=0-7, online=8
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)

---

## 8. commit 历史

```
d477f61 Merge pull request #11 (boot_id offset fix)
9a80fa4 Merge pull request #12 (slide crash fix)
09a60ce revert: NFDS 344→320
2181940 fix: NFDS 320→344 + debug scan address
ae35e8e debug: bruteforce progress trace
e639583 fix: forward declaration for __measure
b3843a1 fix: pile-up verification
d4a35ae fix: futex_init() roundup_pow2
5eb9a62 fix: MM_STRUCT_SZ 0x500→0x3c0
cbc155f fix: KSNITCH_COLLISIONS 4→16
2b0d29b fix: IDENTITY range fix
```
