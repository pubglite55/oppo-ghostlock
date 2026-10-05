# handoff.md

# 项目交接文档

## 项目基本信息

| 项目     | 详情                                                   |
| ------ | ---------------------------------------------------- |
| 项目名称   | oppo-ghostlock                                       |
| 核心定位   | GhostLock CVE-2026-43499 — OPPO Find N2 Linux 内核提权研究 |
| 当前状态   | 已拿到真 root（2026-10-05 起为**零环境变量单条命令**），设备保持健康；当前阻塞 = KernelSU Live |
| 生命周期阶段 | 研究阶段                                                 |
| 仓库地址   | <https://github.com/pubglite55/oppo-ghostlock>       |

## 最新进展(2026-10-05)

轮次记录见 `_docs/handoff/preload一键提权-mt99P-20261005-1400.md`(工作区/设备/证据/未决问题全在其中)。要点:

- 一条零环境变量命令即可拿到真 root,且**设备全程健康**:
  `adb shell "LD_PRELOAD=/data/local/tmp/preloadP.so /system/bin/toybox id"` → `uid=0(root)`。
- 架构从「调用者进程 execve 进下一阶段」改为 **worker + park**:每个 arb write 在独立 worker 子进程里发生,
  写完永久 `pause()`;调用者永不成为写入者。
- 依据(5 次对照):**「fired write 之后对同一个 task 做 execve」**才是设备杀手(999+ `unknown SID` → exec 返回
  ENOENT、binder 挂、framework 塌);单打任一 stage 都无害。
- 完成信号改走**继承 pipe fd**(文件通道在提权后失效);**只回收「未打中」的 worker**(否则重试叠加两套页喷机器会打复位)。
- 取证通道:设备侧 `fsync` 不可信(`/data` = f2fs **`fsync_mode=nobarrier`**),一律走 **trace 直写 caller stdout + host `tee`**。
- 未决:① **KernelSU Live**(`finit_module`/`ksud` 需挪到 hand-off 之前 + 确定性置位 `CAP_SYS_MODULE` bit16);
  ② 每次 fired write 后仍有一次 30~38s 的瞬态 workqueue lockup(会自恢复);③ trigger 对负载敏感(load 200+ 时 0 发)。

## 核心资产清单

### 代码仓库

- 主仓库: `/Users/xiuxiu391/Desktop/oppo/oppo-ghostlock/`
- CyberMeowfia 参考: `/Users/xiuxiu391/Desktop/oppo/CyberMeowfia/`

### 环境地址

- NDK 路径: `/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK`
- IDA Pro: output.elf.i64, imagebase=`0xffffffc008000000`, MCP port 13337

### 设备信息

- 设备: OPPO Find N2 (SM8475/CPH2413)
- Serial: `[redacted]`
- Kernel: `5.10.236-android12-9-o-g74d132f4467a`
- Build: `OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys`
- 安全补丁: 2026-06-01

### 权限账号

> [!NOTE] 待补充：对话中未提及相关信息

## 核心功能与模块

### 已验证通过的功能

| 模块                          | 状态        | 说明                                |
| --------------------------- | --------- | --------------------------------- |
| Firefox CVE-2026-10702      | ✅ Working | SpiderMonkey type confusion → AAW |
| KernelSnitch mm_struct leak | ✅ Working | 7-bug 修复已验证                       |
| GhostLock FUTEX trigger     | ✅ Working | FUTEX_CMP_REQUEUE_PI ret=0        |
| sk_buff reclaim             | ✅ Working | 4/4 send success                  |
| PR #13 KASLR bypass         | ✅ Working | 直接计算 kaslr_base                   |

> [!WARNING]
>   
> **偏移验证修订 (2026-10-04)**: 下表 "已验证" 中的偏移验证结论仅部分成立。经
>   
> `output.elf` `.symtab` 复核(`analysis-scripts/audit_target_offsets.py`):数据符号全部正确;
>   
> 但 `ASHMEM_IOCTL / COMPAT_IOCTL / MMAP / OPEN / RELEASE / SHOW_FDINFO` 六个函数偏移原
>   
> **整体错位一个函数**,已修正。详见 `docs/offset-audit.md`。

### 已确认阻塞的功能

| 模块                       | 状态        | 阻塞原因                 |
| ------------------------ | --------- | -------------------- |
| pselect fd_set 栈覆盖       | ❌ DEAD    | 120B 间隙 + fd_set 堆分配 |
| configfs R/W             | ❌ DEAD    | ashmem 无 configfs 支持 |
| pipe physrw              | ❌ DEAD    | 依赖 configfs          |
| CFI bypass               | ❌ DEAD    | 56+ 方法全失败，无内核写原语     |
| CVE-2026-23274 IDLETIMER | ❌ DEAD    | 需要 CAP_NET_RAW       |
| io_uring                 | ❌ BLOCKED | CFI 太强 + CVE 已修补     |
| fd_set 信息泄露              | ❌ DEAD    | 内核 copy 操作完全隔离       |

## 环境信息

### 开发环境

- macOS (Apple Silicon)
- Android NDK r29
- IDA Pro (MCP integration)

### 设备环境

- Android 16 (BP2A.250605.015)
- kernel 5.10.236
- SELinux Enforcing
- CapEff=0x0000000000000000
- CONFIG_USER_NS 未启用

### 关键配置

```bash
# 编译命令
cd exploit/ && make clean && make NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 部署命令
adb push out/aarch64/libexploit.so /data/local/tmp/preload.so

# 运行命令
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## 已知问题与风险

### 核心阻塞

1. **没有内核写原语** — 所有已知的内核写入路径都被阻塞
2. **pselect fd_set 架构性死路** — 120B 间隙无法克服
3. **ashmem 无 configfs 支持** — pipe physrw 不可用
4. **设备无 root** — 无法触发需要特权的漏洞

### 潜在风险

- 安全补丁 2026-06-01 可能已修补大部分已知 CVE
- 内核 CONFIG_UBSAN_TRAP=y 导致 slide 必然失败
- CONFIG_PANIC_ON_OOPS=y 导致任何 oops 都会 panic

## 待办任务清单

### 优先级 1 (核心阻塞)

- [ ] 寻找新的内核写原语 (可能需要 0-day)
- [ ] 等待 NebuSec 发布 Android GhostLock 方法

### 优先级 2 (替代方案)

- [ ] 评估 ElevateMe rb_erase 路径的可行性 (120B 间隙阻塞)
- [ ] 探索 io_uring 新漏洞可能性

### 优先级 3 (文档完善)

- [ ] 补充 pipe physrw 实现细节
- [ ] 补充 root escalation 实现细节
- [ ] 更新设备安全配置信息

## 交接信息

| 交接节点 | 详情              |
| ---- | --------------- |
| 交接日期 | 2026-07-14      |
| 交接人  | MiMo Code Agent |
| 接收人  | 待定              |

## 后续维护建议

### 日常维护要点

- 定期检查 GitHub Issues 和 PR
- 关注 NebuSec 和 52pojie 社区的新研究
- 关注 kernelCTF 新提交

### 注意事项

- 编译必须使用 `make clean && make`
- 所有内核偏移必须 IDA 验证
- 设备无 root，所有操作在 shell 用户权限下进行
- 不要在 OPPO Find N2 上尝试已确认的 DEAD END 方法
