# 版本更新日志

## [0.3.0] - 2026-07-13

### ✨ 新增功能

- KernelSnitch bruteforce 成功找到 mm_struct 地址
- pile-up verification 添加 timing 验证
- bruteforce progress trace 每 100k candidates 打印扫描地址

### 🐛 问题修复

- **IDENTITY range**: `0xffffffc0-0xffffffc4` → `0xffffff80-0xffffffc0` (direct-map)
- **KSNITCH_COLLISIONS**: 4 → 16 (提高 bruteforce 选择性)
- **MM_STRUCT_SZ**: 0x500 → 0x3c0 (pahole 验证)
- **hashsize alignment**: 添加 `roundup_pow2` 匹配内核行为
- **pile-up verification**: yield 16 次 + 测量 timing 验证
- **forward declaration**: 为 `__measure()` 添加前向声明

### ⚡ 性能优化

- pile-up ratio 从 1.0x 提升到 ~120x
- 碰撞数从 3 提升到 15
- bruteforce 成功找到 mm_struct: `0xffffff8928d6e180`

### 📝 文档更新

- 更新 AGENTS.md 为当前项目状态
- 添加 TROUBLESHOOTING.md 问题排查手册
- 添加 FAQ.md 常见问题
- 添加 CHANGELOG.md 版本更新日志

---

## [0.2.0] - 2026-07-12

### ✨ 新增功能

- GhostLock FUTEX PI 触发成功 (FUTEX_CMP_REQUEUE_PI ret=1)
- KASLR bypass (pselect side-channel) 工作正常
- sk_buff reclaim 4/4 成功

### 🐛 问题修复

- 帧大小修正: sys_futex=0x90, do_futex=0x70, do_select=0x3C0
- IDA 偏移验证: 8 个内核符号地址双重验证
- target.h 更新: pahole + IDA 验证的偏移量

### 📝 文档更新

- 更新 HANDOFF.md 会话交接文档
- 更新 AGENTS.md AI Agent 指南

---

## [0.1.0] - 2026-07-10

### ✨ 新增功能

- 初始项目结构
- exploit 编译系统 (Makefile + NDK)
- KernelSnitch 基础实现
- pselect side-channel 实现

### 📝 文档更新

- 初始 README.md
- 初始 AGENTS.md
- 初始 HANDOFF.md
