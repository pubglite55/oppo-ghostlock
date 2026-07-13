# 开发最佳实践

## 代码规范

### 目录结构

- `exploit/src/` — 主要源代码
- `exploit/src/kernelsnitch/` — KernelSnitch 独立模块
- `exploit/targets/<device>/` — 设备特定配置
- `analysis-scripts/` — 分析脚本
- `test-programs/` — 测试程序

### 命名规范

- 内核偏移: `XXX_OFF` (大写, 如 `ASHMEM_MISC_FOPS_OFF`)
- 函数名: `snake_case` (如 `kernelsnitch_find_collisions`)
- 宏定义: `UPPER_SNAKE_CASE` (如 `KSNITCH_COLLISIONS`)

### 提交规范

每次修改后必须 `git commit`，commit message 格式:
```
type: description

type: fix / feat / debug / revert / docs
```

示例:
```
fix: IDENTITY range 0xffffffc0-ffffffc4 → 0xffffff80-ffffffc0
fix: KSNITCH_COLLISIONS 4 → 16 for better bruteforce selectivity
fix: MM_STRUCT_SZ 0x500 → 0x3c0 (pahole verified)
fix: pile-up verification — yield 16 times + measure timing
debug: add progress trace every 100k candidates
```

## 核心实现原理

### KernelSnitch 堆积机制

KernelSnitch 通过 futex hash 碰撞检测泄漏内核地址:

1. **堆积 (pile-up)**: 4096 线程执行 `FUTEX_WAIT_PRIVATE`，堆积在 hash bucket 128
2. **碰撞检测**: 扫描其他 futex 地址，测量 `FUTEX_WAKE_PRIVATE` timing
3. **bruteforce**: 测试每个 mm_struct 候选，验证所有碰撞地址是否 hash 到同一 bucket

**关键公式**:
```c
futex_hashsize = roundup_pow2(nr_cpu_ids * 256)  // 8 * 256 = 2048
bucket = futex_hash(addr, mm) & (futex_hashsize - 1)
```

### pselect side-channel

利用 pselect 的 fd_set bitmaps 在内核栈上布置数据:
- `core_sys_select` 使用栈缓冲区 v35 (SP+0x50)
- 用户控制的 fd_set 数据通过 `copy_from_user` 写入内核栈
- PI chain walk 读取栈上的 waiter 结构

### GhostLock 触发机制

1. 3 线程模型: waiter / owner / consumer
2. `FUTEX_LOCK_PI` + `FUTEX_WAIT_REQUEUE_PI` → PI 依赖循环
3. `FUTEX_CMP_REQUEUE_PI` 触发 -EDEADLK → 错误回滚
4. `remove_waiter()` 清除 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`

## 优化记录

### pile-up verification 修复

**问题**: 4096 线程异步创建，没有验证是否都已注册为 waiter

**修复**: 在 `__increase()` 中添加:
```c
for (size_t i = 0; i < 16; ++i) sched_yield();
size_t approx_time = __measure((size_t)&ks->inc_futex[id]);
```

**效果**: pile-up ratio 从 1.0x 提升到 ~120x

### hashsize alignment 修复

**问题**: 用 `sysconf(_SC_NPROCESSORS_ONLN)` 而非 `nr_cpu_ids`，且未做 `roundup_pow2`

**修复**: 
```c
unsigned long cpus = sysconf(_SC_NPROCESSORS_ONLN);
unsigned long raw = cpus * 256;
unsigned long result = 1;
while (result < raw) result <<= 1;
futex_hashsize = result;
```

**效果**: hashsize=2048 匹配内核

### KSNITCH_COLLISIONS 优化

**问题**: 只找到 3 碰撞 (target 16)，bruteforce 选择性不足

**修复**: `KSNITCH_COLLISIONS 4 → 16`

**效果**: 碰撞数从 3 提升到 15，bruteforce 成功

## 安全规范

### 设备访问

- 设备没有 root 权限，不能用 strace、kallsyms、dmesg 等 root-only 工具
- `dmesg` 被 SELinux 拒绝: `klogctl: Permission denied`
- `/sys/fs/pstore/` 为空目录，无 ramdump 文件

### 编译安全

- 不要在编译命令中使用 `--no-verify` 等跳过验证的选项
- 保持 `TARGET_CONFIG_H` 宏定义正确，否则 `offset.h` 会报错
