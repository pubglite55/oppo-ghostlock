# 常见问题

## 使用类

### Q: 支持哪些设备？

**A**: 目前仅支持 **OPPO Find N2 (CPH2413/PGU110)**，内核版本 5.10.236。其他设备需要重新提取偏移。

### Q: 需要 root 权限吗？

**A**: 不需要。exploit 通过 Firefox 漏洞获取初始代码执行，然后通过内核漏洞提权。

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
2. 编译内核获取 vmlinux
3. 使用 pahole 提取偏移
4. 更新 `exploit/targets/<device>/target.h`

### Q: 偏移从哪里获取？

**A**: 使用 pahole 从编译的 vmlinux 提取：
```bash
pahole -C task_struct vmlinux
pahole -C cred vmlinux
```

### Q: MM_STRUCT_SZ 和 MM_ORDER 如何确定？

**A**: 
- MM_STRUCT_SZ: 从 pahole 获取 mm_struct 大小，加上 cpumask_size()
- MM_ORDER: 使用 SLUB calculate_order 计算

### Q: 为什么在 macOS 上编译？

**A**: macOS 开发机使用 Android NDK 交叉编译。内核编译需要 Linux 服务器。

---

## 部署类

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

### Q: 如何更新 exploit？

**A**: 
```bash
git pull origin main
NDK=~/Library/Android/android-ndk-r29
# 重新编译
```

---

## 技术类

### Q: KernelSnitch 是什么？

**A**: KernelSnitch 是一个使用 futex 哈希时序侧信道泄漏内核 mm_struct 地址的技术。

### Q: GhostLock 漏洞原理？

**A**: GhostLock (CVE-2026-43499) 是 rtmutex 栈 UAF 漏洞，通过 FUTEX PI 操作触发。

### Q: 为什么 seccomp 会阻止 exploit？

**A**: Firefox 的 seccomp 沙箱阻止了 GhostLock 需要的 FUTEX PI 操作。

### Q: 如何绕过 seccomp 限制？

**A**: 需要使用替代技术，如 PR_SET_MM_MAP 回收栈帧，或修改 seccomp 过滤器。
