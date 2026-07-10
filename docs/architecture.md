# 架构设计文档

## 设计理念

本项目采用**分层利用链**架构，将复杂的内核漏洞利用分解为独立的模块化阶段：

1. **用户态初始访问层**：利用 Firefox 浏览器漏洞获取代码执行
2. **内核信息泄漏层**：通过时序侧信道泄漏内核地址
3. **内核漏洞触发层**：利用 GhostLock 漏洞创建悬空指针
4. **权限提升层**：修改进程凭证获取 root 权限

## 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Firefox 151 Browser                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         CVE-2026-10702 Exploit (JS/WASM)            │   │
│  │  AAW │ AAR │ RW64 │ MPROTECT │ ADDR0F               │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              preload.so (LD_PRELOAD)                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │   │
│  │  │   Slide     │  │  KernelSnitch│  │  GhostLock  │ │   │
│  │  │  (KASLR)    │  │  (mm_struct) │  │  (FUTEX PI) │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │   │
│  │         │                │                │          │   │
│  │         ▼                ▼                ▼          │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │           Pipe Physical R/W                  │   │   │
│  │  │        (内核物理内存读写原语)                  │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  │         │                                           │   │
│  │         ▼                                           │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │           Root Privilege Escalation           │   │   │
│  │  │         (修改 cred 结构体获取 root)            │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块详解

### 1. Firefox Exploit (CVE-2026-10702)

**功能**: 在 Firefox 151 浏览器中获取用户态代码执行

**输入**: Firefox 浏览器访问 exploit 页面
**输出**: AAW (任意地址写)、AAR (任意地址读)、RW64、MPROTECT 原语

**依赖**: Firefox 151.0, 不需要特殊内核配置

**关键实现**:
- 利用 SpiderMonkey JS 引擎漏洞
- 通过 TypedArray 操控获取任意读写
- 使用 WASM 和 mprotect 获取代码执行

### 2. Slide/pselect (KASLR 绕过)

**功能**: 泄漏内核 KASLR 基地址

**输入**: 用户态进程
**输出**: 内核基地址、slide_logger、bootid_data 等地址

**依赖**: 无特殊权限要求

**关键实现**:
- 使用 pselect 系统调用的时序差异
- 扫描内核虚拟地址范围
- 通过多次测量获取准确地址

### 3. KernelSnitch (mm_struct 泄漏)

**功能**: 泄漏内核 mm_struct 地址

**输入**: 用户态进程
**输出**: mm_struct 内核地址

**关键参数** (已验证):
- MM_STRUCT_SZ = 0x3c0 (960 bytes)
- MM_ORDER = 3 (32KB slabs)
- mm_objs_per_slab = 34

**关键实现**:
- 使用 futex 哈希时序侧信道
- 创建碰撞来识别内核 slab
- 扫描 64GB 虚拟地址范围

### 4. GhostLock (CVE-2026-43499)

**功能**: 利用 rtmutex 栈 UAF 创建内核悬空指针

**输入**: 三个 futex 词和三个线程
**输出**: 悬空的 pi_blocked_on 指针

**关键实现**:
- FUTEX_LOCK_PI: 锁定 PI futex
- FUTEX_WAIT_REQUEUE_PI: 带重排队的等待
- FUTEX_CMP_REQUEUE_PI: 带比较的重排队
- 创建 PI 依赖循环触发 -EDEADLK

### 5. Pipe Physical R/W

**功能**: 通过 pipe buffer 实现内核物理内存读写

**输入**: mm_struct 地址
**输出**: 内核物理内存读写原语

**关键实现**:
- 使用 SKB (socket buffer) 操控内核内存
- 通过 pipe buffer 建立物理内存映射
- 实现任意内核地址读写

### 6. Root Privilege Escalation

**功能**: 修改进程凭证获取 root 权限

**输入**: 内核读写原语
**输出**: uid=0 (root)

**关键实现**:
- 找到当前进程的 task_struct
- 修改 cred 结构体的 uid/gid/capabilities
- 绕过 SELinux 强制访问控制

## 核心业务流程

### 完整利用链流程

```
1. 用户访问 exploit 页面
   ↓
2. Firefox exploit 触发 (CVE-2026-10702)
   ↓
3. 获取 AAW/AAR/RW64 原语
   ↓
4. 下载并执行 preload.so (LD_PRELOAD)
   ↓
5. Slide/pselect 泄漏内核基地址
   ↓
6. KernelSnitch 泄漏 mm_struct 地址
   ↓
7. 设置内核页访问 (Pipe Physical R/W)
   ↓
8. 触发 GhostLock 漏洞 (FUTEX PI)
   ↓
9. 创建悬空指针
   ↓
10. 修改 cred 结构体获取 root
```

### KernelSnitch 详细流程

```
1. kernelsnitch_setup() 初始化
   - 分配 256MB 虚拟内存 (ashmem)
   - 设置碰撞参数 (4 collisions)
   ↓
2. kernelsnitch_find_collisions() 查找碰撞
   - 使用 futex 哈希创建碰撞桶
   - 测量时序找到碰撞地址
   ↓
3. kernelsnitch_bruteforce() 暴力搜索
   - 8 个线程并行扫描
   - 扫描范围: 0xffffff8000000000 - 0xffffff9000000000
   - 检查 futex 哈希匹配
   ↓
4. 返回 mm_struct 地址
```

## 技术选型说明

| 技术 | 选择 | 原因 | 对比方案 |
|------|------|------|----------|
| KASLR 绕过 | Slide/pselect | 不需要 futex, 兼容性好 | Prefetch (需要 KPTI 关闭) |
| mm_struct 泄漏 | KernelSnitch | 时序侧信道, 可靠性高 | PR_SET_MM_MAP (更复杂) |
| 内核漏洞 | GhostLock (CVE-2026-43499) | 15年历史, 影响所有 Linux | 其他内核漏洞 |
| 内核读写 | Pipe Physical R/W | 基于 pipe buffer, 稳定 | SKB 其他利用 |
| 权限提升 | cred 修改 | 直接修改进程凭证 | core_pattern (DirtyMode) |

## 安全考虑

- Firefox seccomp 沙箱: Seccomp=2, Seccomp_filters=1
- SELinux: enforcing 模式
- KASLR: 启用 (CONFIG_RANDOMIZE_BASE=y)
- SLUB: 启用随机化 (CONFIG_SLAB_FREELIST_RANDOM=y)

> [!WARNING]
> GhostLock 的 FUTEX PI 操作在 Firefox seccomp 沙箱中被阻止，需要替代技术绕过。
