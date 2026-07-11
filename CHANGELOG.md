# 版本更新日志

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

### 🧪 测试结果
- Cache-based 时序: 失败 (cntvct_el0 精度不足 24MHz)
- 改进时序测量: 失败 (变异系数 106.95%)
- 辅助向量泄漏: 失败 (无内核地址)
- PMCCNTR_EL0: 失败 (需要内核权限)
- /proc/kallsyms: 失败 (kptr_restrict 启用)
- /proc/self/pagemap: 失败 (全零)

### ⚡ 性能优化
- 合并源码目录 (删除 exploit-src/)
- 优化构建流程 (Makefile 自动化)

### 📝 文档更新
- 更新 README.md (修正帧大小和 waiter 位置)
- 更新 HANDOFF.md (修正所有偏移值)
- 更新 AGENTS.md (添加关键帧大小表)
- 更新 slide.c 注释 (修正 waiter 位置)

## v0.3.0 (2026-07-10)

### ✨ 新增功能
- 添加实时日志服务器 (log_server.py)
- 添加 exploit.html 日志上传功能
- 添加 seccomp/FUTEX PI 测试代码

### 🐛 问题修复
- 修复 KernelSnitch MM_STRUCT_SZ 偏移 (0x500 → 0x3c0)
- 修复 MM_ORDER 计算 (验证为 order=3)
- 添加 page_base 检查防止崩溃
- 修复 Firefox 152 降级安装问题

### ⚡ 性能优化
- 优化 KernelSnitch verbose 输出
- 添加详细的调试日志

### 📝 文档更新
- 添加完整的项目文档体系
- 添加问题排查手册
- 添加架构设计文档

## v0.2.0 (2026-07-10)

### ✨ 新增功能
- 添加 FUTEX PI 操作测试
- 添加 seccomp 状态检测
- 添加详细的 KernelSnitch 日志

### 🐛 问题修复
- 修复内核编译缺失 vendor/o 目录
- 修复缺失的 Kconfig 文件
- 修复 cc-wrapper.c forbidden warning
- 修复 CONFIG_WERROR 编译失败
- 修复 mmget_still_valid 未定义错误

### ⚡ 性能优化
- 优化 KernelSnitch 参数配置
- 添加 MM_STRUCT_SZ 和 MM_ORDER 验证

### 📝 文档更新
- 添加环境搭建文档
- 添加问题排查指南

## v0.1.0 (2026-07-10)

### ✨ 新增功能
- 初始 exploit 实现
- Firefox exploit (CVE-2026-10702) 集成
- KernelSnitch mm_struct 泄漏
- Slide/pselect KASLR 绕过
- GhostLock (CVE-2026-43499) 触发
- Pipe Physical R/W
- Root privilege escalation

### 🐛 已知问题
- Firefox seccomp 沙箱阻止 FUTEX PI 操作
- OPPO 设备需要特殊偏移配置
- 部分内核编译问题需要手动修复

### 📝 文档
- 添加项目 README
- 添加快速开始指南
