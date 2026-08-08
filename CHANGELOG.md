# CHANGELOG.md

# 版本更新日志

## [1.1-research] - 2026-08-02

### 🔬 Poll Stamping 分析 (MCAST_JOIN_SOURCE_GROUP)

**新增功能**:
- IDA 验证 MCAST_JOIN_SOURCE_GROUP 栈帧 offset: delta=0x108 (264 字节)
- 实现 UNLOCK_PI 竞态: owner 释放 f_pi_target 唤醒 waiter, pi_blocked_on 残留
- 实现 waiter2 线程: 2 节点 rb-tree 确保 rb_erase 执行 rebalancing
- 修复 errno=35 (EDEADLK): owner 等待 requeue 完成后再阻塞
- rb_payload[0]=fake_fops: rb_set_parent 写原语修正

**测试结果**:
- 轮次 1: offset 0x34, errno=35 → 修复同步顺序
- 轮次 2: offset 0x108, errno=0 → requeue 成功
- 轮次 3: UNLOCK_PI 竞态 → waiter 被唤醒, WRPI ret=0
- 轮次 4: owner sched_setattr → pi_waiters 为空, chain walk 无操作
- 轮次 5: waiter2 (2 节点 rb-tree) → rb_erase 在 waiter 返回用户态前执行

**关键发现**:
- rb_erase 在 waiter 线程上下文中执行 (`rt_mutex_slowlock` → `remove_waiter`)
- spray (MCAST_JOIN_SOURCE_GROUP) 在 waiter 返回用户态后执行
- 时序约束: rb_erase 和 spray 无法重叠, MCAST_JOIN_SOURCE_GROUP 无法作为写原语
- lock 字段残留为 f_pi_target 的 rt_mutex 指针 (有效), 不是 NULL

**新增文档**:
- docs/poll-stamping-mcast-analysis.md: 完整 IDA 分析、offset 计算、测试过程
- docs/poll-stamping-bypass-plan.md: 绕过方案、rb_erase 时序问题

## [1.0-research] - 2026-07-14

### ✨ 新增功能
- Firefox CVE-2026-10702 exploit 在设备上验证通过
- KernelSnitch mm_struct 泄漏 7-bug 修复已验证
- GhostLock FUTEX CMP_REQUEUE_PI 触发成功 (ret=0)
- sk_buff 堆喷射 4/4 send 成功
- PR #13 KASLR bypass 实施完成 (绕过 slide，直接计算 kaslr_base)
- IDA Pro 全量偏移验证 (70+ 偏移)
- CVE-2026-23274 IDLETIMER UAF ARM64 适配 (最终 DEAD END)

### 🐛 问题修复
- 修复 KernelSnitch IDENTITY range 错误 (0xffffff80-0xffffffc0)
- 修复 MM_STRUCT_SZ 错误 (0x500 → 0x3c0)
- 修复 hashsize 未对齐问题 (roundup_pow2)
- 修复 nr_cpu_ids 读取方式 (读取 /sys/devices/system/cpu/possible)
- 修复 pile-up 验证 (sched_yield 16 次)
- 修复 futex_hash_table_size 计算 (使用 futex_hashsize)
- 修复 kaslr_base/text_addr 架构性错误

### ⚡ 性能优化
- KernelSnitch KSNITCH_COLLISIONS 从 4 增加到 16，提升可靠性
- PR #13 bypass 移除 slide.c，直接计算 kaslr_base，100% 可靠

### 📝 文档/配置更新
- 创建 TESTED_METHODS.md (56+ 方法完整记录)
- 创建 AGENTS.md (智能体说明)
- 创建 TROUBLESHOOTING.md (问题排查手册)
- 创建 FAQ.md (常见问题)
- 创建 问题描述.md (项目问题梳理)
- 创建 handoff.md (项目交接文档)
- 创建 CHANGELOG.md (版本更新日志)
- 更新 docs/architecture.md (架构设计文档)
- 更新 docs/setup.md (环境搭建文档)
- 更新 docs/best-practice.md (开发最佳实践)
- 更新 docs/knowledge-notes.md (技术知识沉淀)
- GitHub Issues #10, #15, #16 已回复
- GitHub Issue #17 已创建 (CVE-2026-23274 DEAD END)

## [0.1-research] - 2026-07-12

### ✨ 新增功能
- 克隆 NebuSec/CyberMeowfia 仓库
- 创建 OPPO Find N2 target.h
- IDA Pro 打开 output.elf (MCP port 13337)
- IDA 验证 8 个内核符号地址
- 更新 target.h 3 个偏移

### 📝 文档/配置更新
- 创建 docs/architecture.md
- 创建 docs/setup.md
- 创建 docs/knowledge-notes.md

---

> [!NOTE]
> 版本号格式: `<主版本>-<阶段>`，阶段包括 `research`、`poc`、`release`
