# 版本更新日志

## [0.4.0] - 2026-07-14

### ✨ 新增功能

- PR #13 bypass slide — 跳过 slide leak，直接使用 direct-map kernel base
- PR #13 analysis report — 完整的 PR #13 分析文档

### 🐛 问题修复

- 恢复 SLIDE_* 定义用于 util.c 编译
- 恢复 PSELECT_WAITER_WORD_SHIFT 用于 fops.c 编译
- 使用 P0_DATA_ALIAS_CONST 计算正确的 direct-map 地址

### ⚡ 性能优化

- 跳过 slide leak 后 exploit 启动更快

### 📝 文档更新

- 更新所有文档至最新状态
- 添加 PR #13 analysis report
- 更新 AGENTS.md、HANDOFF.md

---

## [0.3.0] - 2026-07-14

### 🐛 问题修复

- **PR #11 merged**: boot_id 数据偏移修正 `0x02b99acd` → `0x02b99b6d`
- **PR #12 merged**: P0_PAGE_OFFSET `0xffffffc000000000` → `0xffffff8000000000`, P0_KERNEL_PHYS_LOAD `0x80000000` → `0xa8000000`
- NFDS 扫描: 320/321/344/640 全部测试，确认 slide 机制不可行

### 📝 文档更新

- 更新所有文档至最新状态
- 添加 `FRONTEND_STACK_ALLOC=256` 分析
- 添加 NFDS 扫描结果

---

## [0.2.0] - 2026-07-13

### ✨ 新增功能

- KernelSnitch mm_struct 泄漏成功
- pile-up verification 添加 timing 验证
- bruteforce progress trace 每 100k candidates 打印扫描地址

### 🐛 问题修复

- **IDENTITY range**: `0xffffffc0-ffffffc4` → `0xffffff80-ffffffc0`
- **KSNITCH_COLLISIONS**: 4 → 16
- **MM_STRUCT_SZ**: 0x500 → 0x3c0
- **hashsize alignment**: 添加 `roundup_pow2`
- **pile-up verification**: yield 16 次 + timing 测量
- **forward declaration**: 为 `__measure()` 添加前向声明

### ⚡ 性能优化

- pile-up ratio 从 1.0x 提升到 ~120x
- 碰撞数从 3 提升到 15
- bruteforce 成功找到 mm_struct

### 📝 文档更新

- 更新 AGENTS.md 为当前项目状态
- 添加 TROUBLESHOOTING.md 问题排查手册
- 添加 FAQ.md 常见问题
- 添加 CHANGELOG.md 版本更新日志

---

## [0.1.0] - 2026-07-12

### ✨ 新增功能

- 初始项目结构
- exploit 编译系统 (Makefile + NDK)
- KernelSnitch 基础实现
- pselect side-channel 实现

### 📝 文档更新

- 初始 README.md
- 初始 AGENTS.md
- 初始 HANDOFF.md
