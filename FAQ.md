# 常见问题

## 使用类

### Q: 这个 exploit 能 root 所有 OPPO 设备吗?

**A**: 不能。本项目专门针对 OPPO Find N2 (SM8475/CPH2413) 适配。不同设备的内核版本、栈布局、ashmem 类型可能不同，需要重新适配。

### Q: 需要什么权限才能运行?

**A**: 需要 shell 权限 (uid=2000)。不需要 root 或特殊 SELinux 上下文。

### Q: exploit 成功后会显示什么?

**A**: 目前 exploit 尚未完成完整提权链。成功后预期显示:
```
[+] preload starting pid=...
[+] startup context pid=... uid=0(root)
```

---

## 开发类

### Q: 为什么 KernelSnitch 失败了?

**A**: Kernel 5.10 的 `FUTEX_WAKE_PRIVATE` with `val=0` 被优化为不遍历 hash chain，直接返回。诊断测试显示 4096 waiters 时 timing ratio 仅 1.0-1.5x，远低于 KernelSnitch 需要的 10x 阈值。所有基于 futex timing 的碰撞检测在 kernel 5.10 上完全失效。KASLR bypass (pselect) 仍然可用。

### Q: pselect side-channel 能否替代 KernelSnitch 定位 mm_struct?

**A**: 不能。pselect side-channel 泄漏的是内核栈上的数据（nfulnl_logger 地址），用于 KASLR bypass。mm_struct 在 slab 分配器中，不在内核栈上。pselect 泄漏的数据中不包含 current->mm 指针，无法直接推导出 mm_struct 地址。

### Q: 为什么 pselect 不能用于栈回收?

**A**: `set_fd_set()` 使用 `bitmap_alloc()` 在堆上分配内存，用户数据不在内核栈上。即使帧大小匹配，fd_set 数据也无法到达 waiter 位置。

### Q: 为什么 ashmem 打开失败?

**A**: SELinux 限制 shell 域访问 `/dev/ashmem`。解决方法是使用 UUID 后缀路径 (`/dev/ashmem874642ac-...`)，该路径使用不同的 SELinux 类型。

### Q: C ashmem 和 Rust ashmem 有什么区别?

**A**: C ashmem 的 `ashmem_area.name[88]` 与 `configfs_buffer.bin_buffer` 重叠，可以实现类型混淆。Rust ashmem 的字段布局不同，无法利用。

### Q: 帧大小数据是否正确?

**A**: 仓库中的帧大小数据已经过 IDA output.elf 验证修正。旧值 (sys_futex=0x70, do_futex=0x130, do_select=0x390) 均不正确。当前值: sys_futex=0x90, do_futex=0x70, do_select=0x3C0。

---

## 部署类

### Q: 如何在设备上测试?

**A**:
```bash
# 编译
cd exploit && make

# 部署
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"

# 测试
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### Q: 编译时找不到 NDK 怎么办?

**A**:
```bash
# 方法 1: 设置环境变量
export NDK=/tmp/ndk_extract/android-ndk-r29

# 方法 2: 指定 NDK 路径
make NDK=/path/to/ndk
```

### Q: 如何验证 exploit 是否工作?

**A**: 检查输出中是否包含:
- `[+] preload starting pid=...` — preload 加载成功
- `[+] startup context pid=... uid=2000` — 初始上下文正确
- `[+] build config pid=... slide=pselect` — 配置正确

---

## 技术类

### Q: GhostLock 的触发条件是什么?

**A**:
1. CONFIG_FUTEX_PI=y
2. 3 个 futex words (f_wait, f_pi_target, f_pi_chain)
3. 3 个线程 (waiter, owner, consumer)
4. FUTEX_CMP_REQUEUE_PI 竞争条件

### Q: waiter 位置在哪里?

**A**: `stack_top - 0x288` (648B)，从 IDA output.elf 验证。仓库旧值 0x2c8 不正确。

### Q: 为什么需要 mm_struct 地址?

**A**: `prepare_skb_payload()` 需要 mm_struct 地址来计算 SLUB slab 基址，从而布置 fake kernel page。没有 mm_struct 地址，无法设置 fake page，整个 exploit 链无法继续。

### Q: 下一步计划是什么?

**A**:
1. 等待 NebuSec Android blog 发布 stack reclaim 方法
2. 寻找替代 mm_struct 泄漏方法
3. 尝试用 sendmsg cmsg 实现栈回收
