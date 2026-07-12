# 版本更新日志

## v0.5.0 (2026-07-12)

### ✨ 新增功能
- GhostLock 触发验证: FUTEX_CMP_REQUEUE_PI ret=1 ✅
- C ashmem 类型验证: ashmem_area 312 bytes ✅
- configfs_bin_file_operations 找到: bin_buffer at +88 ✅
- ashmem UUID 路径支持: `/dev/ashmem874642ac-...` ✅
- 问题描述文档: 完整问题描述 (发给大佬求助) ✅

### 🐛 问题修复
- 修正帧大小: sys_futex=0x90 (非0x70), do_futex=0x70 (非0x130), do_select=0x3C0 (非0x390)
- 修正 waiter 位置: stack_top-0x288 (非0x2c8)
- 修正 ANON_PIPE_BUF_OPS_OFF: 0x0216aa68 (非0x0216a9c8)
- 修正 SLIDE_NFULNL_LOGGER_OFF: 0x027c14b8 (非0x027c1418)
- 修正 ASHMEM_FOPS_OFF: 0x02c0048 (非0x022bffa8)

### 📝 文档更新
- 更新 README.md: 添加 GhostLock 验证成功状态
- 更新 AGENTS.md: 添加 C ashmem 和 configfs 发现
- 更新 HANDOFF.md: 添加 IDA 分析结果
- 新增 问题描述.md: 完整问题描述 (发给大佬求助)
- 新增 docs/architecture.md: 架构设计文档
- 新增 docs/setup.md: 环境搭建文档
- 新增 docs/best-practice.md: 最佳实践文档
- 新增 docs/knowledge-notes.md: 技术知识沉淀
- 更新 TROUBLESHOOTING.md: 添加 GhostLock 时序问题
- 更新 FAQ.md: 添加 C ashmem 和帧大小问题
- 更新 CHANGELOG.md: 本文件

---

## v0.4.0 (2026-07-12)

### ✨ 新增功能
- 添加 Makefile 自动构建脚本 (NDK 自动检测)
- 添加 mm_struct 泄漏方法测试程序 (test_leak_mm.c)
- 添加内核信息泄漏测试程序 (test_kernel_leak.c)
- 添加 Cache-based 时序攻击测试 (test_cache_timing.c)
- 添加改进时序测量测试 (test_improved_timing.c)
- 添加辅助向量泄漏测试 (test_auxv_leak.c)
- 添加适配指南文档 (docs/adaptation-guide.md)
- 添加 AI Agent 指南 (AGENTS.md)

### 🐛 问题修复
- 修正 INIT_TASK_OFF 偏移 (0x027cbf60 → 0x027cc000)
- 修正帧大小 (vmlinux objdump 验证):
  - __arm64_sys_futex: 0x10 → 0x70 (112B)
  - do_futex: 0x1c0 → 0x130 (304B)
- 修正 waiter 位置: stack_top - 0x358 → stack_top - 0x2c8 (712B)
- 修复 KernelSnitch futex_hashsize:
  - 使用 _SC_NPROCESSORS_CONF 替代 _SC_NPROCESSORS_ONLN
  - 结果: 2048 (8 CPUs * 256)

### 🐛 验证确认
- MM_STRUCT_SZ = 0x3c0 (960B) — pahole 验证
- MM_ORDER = 3 — SLUB 计算验证
- objects_per_slab = 34 — 32KB / 960B

### 📝 文档更新
- 添加 README.md: 项目概述和快速开始
- 添加 CONTRIBUTING.md: 贡献指南
- 添加 TROUBLESHOOTING.md: 问题排查手册
- 添加 FAQ.md: 常见问题
- 添加 docs/architecture.md: 架构设计
- 添加 docs/setup.md: 环境搭建
- 添加 docs/knowledge-notes.md: 技术知识沉淀

---

## v0.3.0 (2026-07-11)

### ✨ 新增功能
- 添加 analysis-scripts/: 内核调用链分析脚本
- 添加 test-programs/: 测试程序集
- 添加 extract-vmlinux: vmlinux 提取工具

### 🐛 问题修复
- 修正 KIMAGE_TEXT_BASE: 0xffffffc008000000 (39-bit VA)
- 修正 P0_PAGE_OFFSET: 0xffffffc000000000

### 📝 文档更新
- 添加 HANDOFF.md: 会话交接文档
- 添加 CHANGELOG.md: 版本更新日志

---

## v0.2.0 (2026-07-10)

### ✨ 新增功能
- 初始 exploit 框架
- KernelSnitch 集成
- GhostLock 触发代码
- pselect KASLR bypass 代码

### 🐛 已知问题
- KernelSnitch mm_struct 泄漏失败 (KPTI)
- pselect fd_set 在堆上 (非栈上)
- KASLR bypass 阻塞

---

## v0.1.0 (2026-07-10)

### ✨ 新增功能
- 项目初始化
- 仓库结构搭建
- 基本文档
