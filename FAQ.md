# 常见问题

## 使用类

### Q: 支持哪些设备？

**A**: 目前仅支持 **OPPO Find N2 (CPH2413/PGU110)**，内核版本 5.10.236。其他设备需要重新提取偏移。

### Q: 需要 root 权限吗？

**A**: exploit 本身不需要 root，但某些信息泄漏方法需要 root 权限。当前 KernelSnitch 失败是因为 KPTI 启用。

### Q: 会损坏设备吗？

**A**: exploit 失败时可能导致手机重启，但不会损坏设备。建议在测试设备上运行。

### Q: Firefox 版本要求？

**A**: 必须使用 **Firefox 151.0**。CVE-2026-10702 漏洞仅存在于此版本。

### Q: exploit 成功的标志是什么？

**A**: 成功后会显示 `uid=0(root)`，并且壁纸会更改（如果安装了 wallpaper）。

---

## 开发类

### Q: 如何添加新设备支持？

**A**:
1. 获取设备的 boot.img
2. 从 OPPO 内核源码编译 vmlinux (需要 DWARF 调试信息)
3. 使用 pahole 提取偏移
4. 更新 `exploit/targets/<device>/target.h`

### Q: 偏移从哪里获取？

**A**: 使用 pahole 从编译的 vmlinux 提取：
```bash
pahole -C task_struct vmlinux
pahole -C cred vmlinux
pahole -C mm_struct vmlinux
```

### Q: MM_STRUCT_SZ 和 MM_ORDER 如何确定？

**A**:
- MM_STRUCT_SZ: 从 pahole 获取 mm_struct 大小，加上 cpumask_size()
- MM_ORDER: 使用 SLUB calculate_order 计算

### Q: 为什么在 macOS 上编译？

**A**: macOS 开发机使用 Android NDK 交叉编译。内核编译需要 Linux 服务器。

### Q: 帧大小为什么之前是错的？

**A**: 之前的帧大小是从服务器编译的 vmlinux 获取的，但服务器 vmlinux 与设备实际内核不匹配。正确的方法是从 OPPO 内核源码编译 vmlinux，然后用 objdump 验证。

### Q: 如何验证帧大小？

**A**: 使用 objdump 反汇编 vmlinux：
```bash
aarch64-linux-gnu-objdump -d vmlinux | grep -A 5 "<do_futex>:"
# 查找 SUB SP, SP, #imm 指令
```

---

## 部署类

### Q: 如何编译 exploit？

**A**:
```bash
cd exploit
make                    # 自动检测 NDK
make NDK=/path/to/ndk  # 指定 NDK 路径
```

### Q: 如何部署到设备？

**A**:
```bash
adb push preload.so /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/preload.so"
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### Q: 服务器需要什么配置？

**A**:
- Python 3.8+
- 端口 8080 (exploit 服务器)
- 端口 8081 (日志服务器)
- 与手机同一网络

### Q: 如何查看实时日志？

**A**: 在浏览器访问 `http://<开发机IP>:8081`

### Q: exploit 失败后如何调试？

**A**:
1. 查看 `http://<开发机IP>:8081` 日志
2. 检查 KernelSnitch 输出
3. 验证偏移是否正确
4. 检查 seccomp 状态

---

## 技术类

### Q: KernelSnitch 是什么？

**A**: KernelSnitch 是一个使用 futex 哈希时序侧信道泄漏内核 mm_struct 地址的技术。

### Q: GhostLock 漏洞原理？

**A**: GhostLock (CVE-2026-43499) 是 rtmutex 栈 UAF 漏洞，通过 FUTEX PI 操作触发。

### Q: 为什么 KernelSnitch 失败？

**A**: 因为 KPTI 启用 (CONFIG_UNMAP_KERNEL_AT_EL0=y)，导致时序侧信道不准确。cntvct_el0 精度不足，PMCCNTR_EL0 需要内核权限。

### Q: waiter 位置是多少？

**A**: `stack_top - 0x2c8` (712B)，从 vmlinux objdump 验证。

### Q: 为什么需要等 NebuSec blog？

**A**: NebuSec 已确认将在下一篇 Android blog 中讨论 Android 上的 stack reclaim 和 ASLR bypass 方法。这是当前最可行的方向。
