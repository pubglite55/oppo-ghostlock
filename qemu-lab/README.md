# qemu-lab — arm64 5.10 guest for stage testing

用 QEMU 跑一个与目标同代(5.10.x)的 arm64 Linux,把有风险的 exploit 阶段挪到这里试,
好拿到真机上拿不到的完整 dmesg / panic 输出。

**建成并跑通,但结论是:对本漏洞价值有限** —— 详见 `docs/matisse-port.md §7`。

## 一句话结论

| 能做 ✔ | 不能做 ✗ |
|---|---|
| 验证移植本体能跑(页喷射/KernelSnitch/触发机制) | 复现**依赖 CPU 时序**的泄露与竞态(`perf` 泄露、futex 抢占) |
| 拿完整内核日志、定结构偏移 | —— |

原因:本机 QEMU 只编了 `tcg`(纯软件模拟),时序失真;硬件虚拟化(WHPX/KVM)在 Windows 的
arm64 客户机上不可用。**因此 C 阶段的"能不能打中"无法在虚机里验证。**

## 文件

| 文件 | 作用 |
|---|---|
| `init.c` | 静态 `init`(NDK `--target=aarch64-linux-android35 -static`)。挂 proc/sys/dev,打印版本/KASLR/perf/kptr_restrict,转储 kallsyms,放开 `perf_event_paranoid=-1`,自动带 C 阶段环境跑 `/data/exploit_static`,然后进 REPL(`cat <path>` / `kallsyms` / `run` / `reboot`) |
| `lab_main.c` | 给 exploit 的构造函数一个 main(它是 `LD_PRELOAD` 形态的入口) |
| `extract_deb.py` | 本机无 `ar`/`dpkg-deb`,纯 stdlib 解 `.deb` |
| `mkinitramfs.py` | 本机无 `cpio`,纯 stdlib 造 **newc** cpio + gzip |
| `derive_qemu_target.py` | 从带符号 `vmlinux` 反汇编出该内核的偏移 |
| `target-debian-5.10.218.h` | 推导出的 guest 版 target(cred `0x6c0/0x6c8`、`tasks` `0x560`、alias 恒等) |

## 步骤

```bash
# 1. 取料(国内镜像快)
#    qemu-w64-setup-*.exe                        官方 Windows 构建(winget 在非交互环境会失败)
#    linux-image-5.10.0-30-arm64-unsigned_*.deb  -> boot/vmlinuz-5.10.0-30-arm64
#    linux-image-5.10.0-30-arm64-dbg_*.deb       -> vmlinux(带符号,726MB)
#    busybox-static_*_arm64.deb                  (可选;静态 init 更好)
python extract_deb.py <deb> <dir>

# 2. 造 initramfs(init.bin 由 init.c 编译而来;有 init.bin 时优先用它)
clang --target=aarch64-linux-android35 -static -O2 -o init.bin init.c
python mkinitramfs.py

# 3. 启动(nokaslr ⇒ 地址固定,不需要任何泄露)
qemu-system-aarch64.exe -machine virt -cpu cortex-a72 -smp 2 -m 1536 \
  -kernel kx/boot/vmlinuz-5.10.0-30-arm64 -initrd initramfs.cpio.gz \
  -append "console=ttyAMA0 earlycon=pl011,0x9000000 nokaslr" -nographic -no-reboot
```

## 踩过的坑(都已修,勿重犯)

- **newc cpio 头在 magic 之后是 13 个字段**(ino, mode, uid, gid, nlink, mtime, filesize,
  devmajor, devminor, rdevmajor, rdevminor, namesize, check)。字段数/顺序错 ⇒ 内核解出空 rootfs。
  目录要 `S_IFDIR` + nlink=2,符号链接 `S_IFLNK` 且 data 是目标路径。
- **init 必须是静态二进制**;busybox 脚本形态的 `/init` 会 `No working init found`。
- `clang` / `adb` / `qemu*.exe` 是**原生 Windows 程序,不认 MSYS `/c/...`**;传 `C:/...`,相对路径要先 `cd` 进树。
- 编 exploit 需要 `-DTARGET_CONFIG_H="targets/<proj>/target.h"`。
- `winget install` 在无 tty 环境报 `stdin is not a tty` ⇒ 用官方直连安装包。
- **偏移必须按内核重算**:Debian 的 cred 是 `0x6c0/0x6c8`,OPPO 是 `0x778/0x780`。