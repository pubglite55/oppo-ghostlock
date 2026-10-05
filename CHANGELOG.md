# CHANGELOG.md

# 版本更新日志

> 状态（2026-10-05 冻结）：历史更新日志逐条保留；最新冻结状态见文末追加的 [2.0-preload]。

## [1.2-research] - 2026-10-04

### 🔧 偏移审计与修复 (output.elf 实测)

**修复**:
- 修正 `target.h` 中 ashmem 函数偏移(原整体错位一个函数):
  `ASHMEM_IOCTL/COMPAT_IOCTL/MMAP/OPEN/RELEASE/SHOW_FDINFO` → 正确符号地址
- 补充 `ASHMEM_LLSEEK_OFF` / `ASHMEM_READ_ITER_OFF` 并导出对应宏
- 更正 `docs/knowledge-notes.md` 的 `file_operations` 偏移表
  (本 build `unlocked_ioctl` 在 0x50,自该字段起整体 +8)

**新增**:
- `analysis-scripts/audit_target_offsets.py` — 纯 stdlib(无需 pyelftools/IDA)的偏移审计脚本
- `docs/offset-audit.md` — 完整审计报告(方法/证据/修正值)

**死代码清理**(无调用者,已移出构建并加注记):
- `slide.c` — pselect boot_id KASLR 泄漏,已被 PR #13 直接映射取代
- `heap_spray.c` — 与 pipe physrw 循环依赖,无法自举
- `fops.c::do_pselect_fake_lock_route()` — 无调用者

**验证结果**: `audit_target_offsets.py` → **exact=22 / mismatch=0**。

**修订说明**: 此前 "IDA Pro 全量偏移验证 (70+ 偏移)" 仅部分成立 — 数据符号全部正确,
但 ashmem 函数指针 6 项系统性错位。详见 `docs/offset-audit.md`。

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

## [2.0-preload] - 2026-10-05

> 冻结状态附录（旧条目逐条保留不动）。

### ✨ 零环境变量单条命令真 root（已复现）

- 一条命令即可拿到真 root，且提权体现在**调用者自己的进程**内：
  `adb shell "LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/toybox id"` → `uid=0(root)`。
- 产物 `preload.so` sha256 `b5128c725216aad1464bc5c54e39bb2d980c2b3a474adc17278a4f9100acdb54`（214,040 B）。
- 链路：autopwn 编排器 → stage 1（SELinux→Permissive，`TREE_PC=ffffff802aa793c0 / TREE_RIGHT=SPRAY`）
  → stage 2（CAPS-ONLY 写 `cred->cap_effective`）→ `setresgid/setresuid(0,0,0)` → hand-off `execve`
  原始命令行 → 调用者打印 `uid=0` → worker `pause()` park。

### ⚠️ 已知边界（冻结原因）

- **KernelSU 未 Live**：`ksud late-load` 从已安装 manager APK 取模块（本机未装 ⇒ 静默 `rc=0`）；
  `ksud insmod` 死于 `Cannot parse kallsyms`（需 `CAP_SYSLOG`）；唯一可行 `finit_module(ko_fd,"",3)`，
  只差 `CAP_SYS_MODULE(bit16)`，而 bit16 无法确定性置位 ⇒ 剩余是抽奖。官方 KO
  `lkm-aarch64-android12-5.10`（349,936 B）与本机同 KMI。
- **健康代价**：约一半运行在写入落地后 framework 会塌；未命中的发也可能打死设备（prep 机器本身）。
  **唯一有效软重启 = `adb shell 'svc power reboot'`**（其它全部无效），且必须用 `boot_id` 变化验证。

### 📝 文档更新
- 追加本条冻结状态附录；旧条目不作改动。
- 权威记录：[`_docs/handoff/preload一键提权-mt99K-20261005-1600.md`](_docs/handoff/preload一键提权-mt99K-20261005-1600.md)。

---

> [!NOTE]
> 版本号格式: `<主版本>-<阶段>`，阶段包括 `research`、`poc`、`release`
