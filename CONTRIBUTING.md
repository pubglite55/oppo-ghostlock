# 贡献指南

感谢你对 GhostLock OPPO Find N2 项目的关注！

## 贡献方式

### 报告 Bug

1. 搜索 [Issues](https://github.com/your-username/oppo-ghostlock/issues) 确认问题未被报告
2. 使用 [Bug 反馈模板](.github/ISSUE_TEMPLATE/bug_report.md) 提交
3. 提供详细的复现步骤和日志

### 提交功能建议

1. 搜索 [Issues](https://github.com/your-username/oppo-ghostlock/issues) 确认建议未被提出
2. 使用 [功能建议模板](.github/ISSUE_TEMPLATE/feature_request.md) 提交
3. 说明需求背景和期望功能

### 提交代码

1. Fork 仓库
2. 创建功能分支: `git checkout -b feature/your-feature`
3. 提交更改: `git commit -m 'feat: add your feature'`
4. 推送分支: `git push origin feature/your-feature`
5. 创建 Pull Request

## Issue 提交规范

### Bug 反馈

```markdown
## 问题描述
简要描述遇到的问题

## 复现步骤
1. 打开 Firefox 151
2. 访问 exploit 页面
3. ...

## 预期行为
描述期望的结果

## 实际行为
描述实际发生的情况

## 环境信息
- 设备: OPPO Find N2
- 内核: 5.10.236
- Firefox: 151.0

## 日志/截图
粘贴相关日志或截图
```

### 功能建议

```markdown
## 需要背景
描述当前的限制或痛点

## 期望功能
描述期望的功能

## 替代方案
描述其他可能的解决方案

## 补充说明
其他相关信息
```

## 本地开发贡献步骤

### 1. 环境准备

```bash
# 克隆仓库
git clone https://github.com/your-username/oppo-ghostlock.git
cd oppo-ghostlock

# 安装依赖
brew install android-ndk android-platform-tools
```

### 2. 创建分支

```bash
git checkout -b feature/your-feature
```

### 3. 开发测试

```bash
# 编译 exploit
NDK=~/Library/Android/android-ndk-r29
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang \
  --target=aarch64-linux-android35 \
  --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
  -I. -O2 -fPIC -shared \
  -DTARGET_CONFIG_H="exploit/targets/oppo-find_n2/target.h" \
  exploit/src/*.c exploit/src/*.S \
  -pthread -o preload.so

# 测试
adb push preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### 4. 提交代码

```bash
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature
```

## 代码审核标准

### 必须满足

- [ ] 代码编译通过
- [ ] 在目标设备上测试通过
- [ ] 不会导致设备崩溃
- [ ] 偏移配置正确
- [ ] 文档更新

### 推荐

- [ ] 添加单元测试
- [ ] 更新 README
- [ ] 更新 CHANGELOG
- [ ] 添加调试日志

## 行为准则

- 尊重其他贡献者
- 提供建设性的反馈
- 专注于技术问题
- 遵守 responsible disclosure 原则

## 许可证

贡献的代码将按照 GPL-3.0 协议开源。
