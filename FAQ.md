# FAQ.md

# 常见问题

## 使用类

### Q: 如何编译 exploit？

```bash
cd exploit/
make clean && make NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK
```

### Q: 如何部署到设备？

```bash
adb push out/aarch64/libexploit.so /data/local/tmp/preload.so
adb shell chmod 755 /data/local/tmp/preload.so
```

### Q: 如何运行 exploit？

```bash
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

### Q: 编译时为什么必须 `make clean && make`？

Makefile 不追踪 .h 文件变化，修改 .h 后必须 clean 再 make。

### Q: 为什么不能使用 android35 API？

android35 会导致 shadow stack OOM。NDK r29 的 android35 对 shadow stack 支持不完整。

## 开发类

### Q: 如何验证内核偏移？

使用 IDA Pro 打开 `boot_unpacked/output.elf`，通过 MCP 端口 13337 连接。所有偏移必须 IDA + pahole 双重验证。

### Q: 为什么 pselect fd_set 栈覆盖不可行？

两个原因：
1. NFDS > 336: fd_set 通过 `bitmap_alloc()` 分配在堆上
2. NFDS ≤ 336: fd_set 在栈上，但 waiter 在 fd_set 下方 120 字节，无法覆盖

### Q: 为什么 configfs R/W 不可行？

OPPO 内核的 ashmem 驱动没有 configfs 支持。`CONFIG_ASHMEM_CONFIGFS` 未启用，pread 返回 EOF。

### Q: 为什么 CVE-2026-23274 不可行？

漏洞触发链每一步都需要 CAP_NET_RAW，而设备无 root + CONFIG_USER_NS=n，无法获取 capabilities。

### Q: KernelSnitch 的 MM_STRUCT_SZ 为什么是 0x3c0？

通过 pahole 验证 OPPO Find N2 的 mm_struct 实际大小为 960 bytes (0x3c0)，与仓库默认值 0x500 不同。

## 部署类

### Q: 设备无法连接 adb 怎么办？

1. 检查 USB 调试是否启用
2. 检查 USB 线是否正常
3. 尝试重启 adb server: `adb kill-server && adb start-server`

### Q: 设备没有 root 能运行 exploit 吗？

可以。本项目所有 exploit 都设计为在无 root 环境下工作。

### Q: 如何获取设备内核版本？

```bash
adb shell uname -r
# 输出: 5.10.236-android12-9-o-g74d132f4467a
```

### Q: 如何获取设备安全配置？

```bash
adb shell zcat /proc/config.gz | grep CONFIG_FUTEX_PI
```

### Q: exploit 运行后没有输出怎么办？

1. 检查 preload.so 是否正确推送
2. 检查 LD_PRELOAD 路径是否正确
3. 检查 SELinux 是否阻止了加载
