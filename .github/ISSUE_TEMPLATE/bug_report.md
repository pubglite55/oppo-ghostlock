---
name: Bug Report
about: 报告 exploit 中的问题
title: '[BUG] '
labels: bug
assignees: ''
---

## 问题描述

<!-- 简要描述遇到的问题 -->

## 复现步骤

1. `adb push build/oppo-find_n2/bin/preload.so /data/local/tmp/preloadP.so`
2. `adb shell "LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/toybox id"`
3. 观察输出与设备状态（`uptime`、`boot_id`、framework）
4. 看到错误

## 预期行为

<!-- 描述期望的结果 -->

## 实际行为

<!-- 描述实际发生的情况 -->

## 环境信息

- **设备**: OPPO Find N2 (PGU110/SM8475)
- **内核版本**: 5.10.236-android12-9-o-g74d132f4467a
- **产物**: preloadP.so (`sha256 b5128c72…`, 214,040 B)
- **Android 版本**: 16 (BP2A.250605.015)

## 日志/截图

<!-- 粘贴 exploit 输出日志或截图 -->

```
在此粘贴日志
```

## 其他信息

<!-- 其他有助于诊断问题的信息 -->
