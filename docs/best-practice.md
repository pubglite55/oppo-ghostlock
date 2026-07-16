# docs/best-practice.md

# 开发最佳实践

## 代码规范

### 目录结构规范

- `exploit/src/` — 核心 exploit 源码
- `exploit/src/targets/` — 设备特定配置
- `test-programs/` — 独立测试程序
- `analysis-scripts/` — 分析脚本
- `docs/` — 文档

### 文件命名规范

- 源码文件: 小写下划线 (`kernelsnitch.h`, `futex_hash.h`)
- 测试文件: `test_` 前缀 (`test_io_uring.c`)
- 文档文件: 小写连字符 (`knowledge-notes.md`)

### 编码约定

- 所有内核偏移通过 IDA output.elf 验证
- 不信任仓库默认值，必须 pahole + IDA 双重验证
- 每次修改后 git commit

### Git 提交规范

```
<type>: <description>

# type: feat, fix, docs, refactor, test
# description: 简短描述修改内容
```

## 核心实现原理

### KernelSnitch futex hash timing

**原理**: 利用 futex hash table 的冲突检测机制泄漏内核地址。

**执行链路**:
1. 创建多个线程竞争同一 futex key
2. 内核将竞争线程放入同一 hash bucket
3. 测量 `futex_wake` 时序差异
4. mm_struct 地址反映在时序中

**关键代码位置**:
- `exploit/src/kernelsnitch/kernelsnitch.h` — 核心泄漏逻辑
- `exploit/src/kernelsnitch/futex_hash.h` — hash 修复

### GhostLock FUTEX 触发

**原理**: 通过 `FUTEX_CMP_REQUEUE_PI` 竞态创建悬空指针。

**执行链路**:
1. waiter 调用 `FUTEX_WAIT_REQUEUE_PI`
2. owner 调用 `FUTEX_CMP_REQUEUE_PI`
3. 竞态条件下 `pi_blocked_on` 指针悬空
4. 后续操作通过悬空指针访问已释放内存

**关键代码位置**:
- `exploit/src/main.c` — GhostLock 触发逻辑
- `exploit/src/fops.c` — pselect fake lock route

### P0_DATA_ALIAS_CONST 地址计算

**原理**: OPPO 内核使用特殊的地址别名机制。

**计算公式**:
```c
P0_DATA_ALIAS_CONST(addr) = P0_PAGE_OFFSET | ((addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA)
// P0_KERNEL_PHYS_DELTA = P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET = 0x28000000
```

**错误示例**:
```c
// 错误: 使用内核镜像映射地址
KIMAGE_TEXT_BASE + 0x02b99b6d → 0xffffffc0ab99b6d

// 正确: 使用直接映射地址
P0_DATA_ALIAS_CONST(...) → 0xffffff802ab99b6d
```

## 优化记录

### KernelSnitch 7-bug 修复

| Bug | 问题现象 | 根因 | 优化方案 | 效果 |
|-----|----------|------|----------|------|
| IDENTITY range | mm_struct 泄漏失败 | 范围错误 | `0xffffff80-0xffffffc0` | ✅ 泄漏成功 |
| KSNITCH_COLLISIONS | 碰撞检测不足 | 值太小 | 4 → 16 | ✅ 可靠性提升 |
| MM_STRUCT_SZ | 结构体大小错误 | 默认值错误 | 0x500 → 0x3c0 | ✅ 匹配实际大小 |
| hashsize 未对齐 | hash table 大小错误 | 缺少对齐 | `roundup_pow2()` | ✅ 正确对齐 |
| pile-up 验证 | 线程未阻塞 | 缺少 yield | `sched_yield` 16 次 | ✅ 验证通过 |
| futex_hash_table_size | hash table 错误 | 计算错误 | 使用 `futex_hashsize` | ✅ 正确大小 |
| nr_cpu_ids | CPU 数量错误 | 读取方式错误 | 读取 `/sys/devices/system/cpu/possible` | ✅ 正确值 8 |

### PR #13 KASLR bypass

| 问题 | 根因 | 优化方案 | 效果 |
|------|------|----------|------|
| slide pselect crash | UBSAN_TRAP 触发 BRK | 绕过 slide，直接计算 kaslr_base | ✅ 100% 可靠 |

## 安全规范

### 设备安全配置

- `CONFIG_FUTEX_PI=y` — GhostLock 触发前提
- `CONFIG_UNMAP_KERNEL_AT_EL0=y` — KPTI 启用
- `CONFIG_UBSAN_TRAP=y` — slide 必然失败
- `CONFIG_PANIC_ON_OOPS=y` — 触发 panic
- `CONFIG_SECCOMP=y` — seccomp 启用
- `CONFIG_SECURITY_SELINUX=y` — SELinux Enforcing

### 权限限制

- `CapEff=0x0000000000000000` — 无任何 capabilities
- `CONFIG_USER_NS` 未启用 — 无法 CLONE_NEWUSER
- SELinux Enforcing — 阻止 BPF/ashmem/userfaultfd
- kptr_restrict 启用 — /proc 信息泄露不可用

> [!WARNING]
> 设备无 root，所有操作必须在 shell 用户权限下进行。
