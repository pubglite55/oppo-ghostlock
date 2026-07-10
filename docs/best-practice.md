# 开发最佳实践

## 代码规范

### 目录结构规范

```
exploit/
├── targets/           # 设备特定配置
│   └── <device>/      # 按设备名组织
│       └── target.h   # 偏移配置
└── src/               # 源代码
    ├── main.c         # 主入口
    ├── *.c            # 功能模块
    └── kernelsnitch/  # 依赖库
```

### 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 宏定义 | UPPER_SNAKE_CASE | `MM_STRUCT_SZ` |
| 函数 | lower_snake_case | `slide_leak_kernel_base()` |
| 结构体 | lower_snake_case | `struct kernelsnitch_shared_state` |
| 文件名 | lower_snake_case | `util.c` |

### 提交规范

```
<type>(<scope>): <subject>

type:
  feat: 新功能
  fix: 修复
  docs: 文档
  style: 格式
  refactor: 重构
  test: 测试
  chore: 构建/工具

scope: exploit, docs, server
subject: 简短描述
```

## 核心实现原理

### KernelSnitch mm_struct 泄漏原理

KernelSnitch 使用 **futex 哈希时序侧信道** 泄漏内核 mm_struct 地址：

1. **碰撞查找**: 创建多个 futex 地址，找到哈希碰撞对
2. **暴力搜索**: 扫描内核虚拟地址范围，检查 futex 哈希值
3. **时序测量**: 通过 futex 操作的时序差异判断地址是否有效

关键参数:
- mm_struct 大小: 960 bytes (0x3c0)
- slab order: 3 (32KB slabs)
- 每个 slab 对象数: 34
- 碰撞数: 4

### Slide/pselect KASLR 绕过原理

使用 pselect 系统调用的时序差异泄漏内核地址：

1. 创建大量 pselect 监听
2. 测量不同地址的访问时序
3. 通过统计分析确定内核基地址

### GhostLock 漏洞原理

GhostLock (CVE-2026-43499) 是一个 **栈 UAF** 漏洞：

1. **触发条件**: 三个 futex 词 + 三个线程创建 PI 依赖循环
2. **漏洞点**: `remove_waiter()` 清除错误任务的 `pi_blocked_on`
3. **利用方式**: 回收栈帧，伪造 `rt_mutex_waiter` 结构体

## 优化记录

### KernelSnitch 偏移修复

**问题**: mm_struct 泄漏失败
**原因**: MM_STRUCT_SZ 和 MM_ORDER 值错误
**修复**:
```c
// 修复前
#define MM_STRUCT_SZ 0x500  // 错误
#define MM_ORDER 3

// 修复后 (pahole 验证)
#define MM_STRUCT_SZ 0x3c0  // 960 bytes (包含 cpumask)
#define MM_ORDER 3          // SLUB calculate_order 结果
```

### VMLinux 编译修复

**问题**: OPLUS 内核源码编译失败
**原因**: 缺失 vendor/o 目录和多个 Kconfig 文件
**修复**:
1. 下载模块仓库并复制 vendor/o
2. 创建缺失的 Kconfig 文件
3. 修复 cc-wrapper.c 的 forbidden warning 检查
4. 禁用 CONFIG_WERROR
5. 添加 mmget_still_valid 宏定义

### Firefox 151 降级

**问题**: exploit 需要 Firefox 151，但设备安装了 152
**修复**:
```bash
adb install -d fenix-151.0.apk  # -d 允许降级安装
```

## 安全规范

### 权限控制

- Exploit 仅在测试设备上运行
- 不对生产环境进行测试
- 遵守 responsible disclosure 原则

### 数据安全

- 不在日志中暴露敏感信息
- 使用 HTTPS 传输 exploit 文件 (生产环境)

### 异常处理

- Exploit 失败时不应导致设备崩溃
- 添加 page_base 检查防止无效内存访问
- 使用 Seccomp=2 状态监控沙箱限制
