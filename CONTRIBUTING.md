# 贡献指南

> 状态（2026-10-05 冻结）：本项目已达成「零环境变量单条命令真 root（uid=0）」（产物 `preloadP.so`，sha256 `b5128c72…`，214,040 B）；KernelSU 未 Live。当前构建走 `bash C:/Users/L1872/Desktop/oppo-2/build_v29.sh`，产物在 `exploit-v29/build/oppo-find_n2/bin/preload.so`。最新权威记录见 [`_docs/handoff/preload一键提权-mt99K-20261005-1600.md`](_docs/handoff/preload一键提权-mt99K-20261005-1600.md)。

感谢你对本项目的关注！本项目是 OPPO Find N2 上 GhostLock (CVE-2026-43499) 漏洞利用的研究项目。

## 贡献方式

### 报告问题

如果你发现了 bug 或有改进建议，请创建 [Issue](https://github.com/pubglite55/oppo-ghostlock/issues)。

### 提交代码

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交你的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建一个 Pull Request

## 开发规范

### 代码风格

- 使用 2 空格缩进
- 函数名使用小写下划线
- 宏定义使用大写下划线
- 变量名使用小写下划线

### 提交信息

- 使用中文或英文
- 简洁明了地描述更改内容
- 使用 `feat:`, `fix:`, `docs:` 等前缀

### 测试

- 确保代码能在 OPPO Find N2 上编译和运行
- 测试关键功能点
- 更新相关文档

## 免责声明

本项目仅供安全研究和教育目的。未经授权对他人设备进行测试是违法的。贡献者应确保其贡献符合相关法律法规。
