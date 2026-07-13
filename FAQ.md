# 常见问题

## 使用类

### Q: 如何编译 exploit？

```bash
cd exploit/
make NDK=/tmp/ndk_extract/android-ndk-r29
```

输出: `preload.so` (128KB)

### Q: 如何部署到设备？

```bash
adb push preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

### Q: 成功标志是什么？

```
[+] preload starting pid=...
[*] parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (16)
[*] pile-up verified: approx_time=...
[*] prepare_kernel_page leaked_mm=...
```

### Q: 为什么设备没有 root 权限？

OPPO Find N2 是用户版本，没有 root 权限。不能用 strace、kallsyms、dmesg 等 root-only 工具。

### Q: 如何获取 kernel 日志？

> [!NOTE]
> 设备 kernel 日志完全不可访问:
> - `dmesg` → SELinux deny syslog_read
> - `/sys/fs/pstore/` → 空目录
> - logcat 无 kernel panic 日志

---

## 开发类

### Q: 为什么不能用仓库默认的帧大小？

仓库中的帧大小全部错误:
- sys_futex: 0x70 (旧) → 0x90 (IDA 验证)
- do_futex: 0x130 (旧) → 0x70 (IDA 验证)
- do_select: 0x390 (旧) → 0x3C0 (IDA 验证)

**必须使用 IDA output.elf 验证的值。**

### Q: 为什么 IDENTITY 范围是 0xffffff80-0xffffffc0？

mm_struct 由 slab 分配器在 direct-map 范围中分配。ARM64 39-bit VA 的 direct-map 范围是 `0xffffff8000000000-0xffffffc000000000` (16GB)。

旧值 `0xffffffc0-0xffffffc4` 是 kernel image 范围，不包含 slab 分配。

### Q: 为什么 KSNITCH_COLLISIONS 要设为 16？

更多碰撞数 = 更严格匹配 = 更少假阳性。设为 4 时只找到 3 碰撞，bruteforce 选择性不足。设为 16 后找到 15 碰撞，bruteforce 成功。

### Q: 为什么 pile-up 需要验证？

原始代码只 yield 2 次，线程可能还没全部 block 就开始测量。添加 pile-up verification 后，ratio 从 1.0x 提升到 ~120x。

### Q: 为什么 hashsize 要用 roundup_pow2？

内核使用 `roundup_pow_of_two(nr_cpu_ids * 256)` 计算 hashsize。用户态必须匹配内核行为，否则 hash bucket 不一致。

---

## 部署类

### Q: NDK 版本有什么要求？

必须使用 NDK r29 的 `aarch64-linux-android35-clang`。使用其他版本可能导致 shadow stack OOM。

### Q: 设备需要什么条件？

- OPPO Find N2 (SM8475/CPH2413)
- Kernel 5.10.236
- CONFIG_FUTEX_PI=y
- USB 调试模式

### Q: exploit 失败会怎样？

exploit 失败可能导致设备重启 (kernel panic)。这是正常现象，重启后可重新测试。

### Q: 如何回滚到之前的版本？

```bash
git log --oneline  # 查看 commit 历史
git checkout <commit-hash> -- exploit/
make clean && make NDK=/tmp/ndk_extract/android-ndk-r29
```
