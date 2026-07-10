# 版本更新日志

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
