---
name: offset-verify
description: 从服务器 vmlinux 验证内核偏移和帧大小
---

# Offset Verify

从服务器上的 OPPO 内核源码编译的 vmlinux 验证内核偏移和帧大小。

## 使用时机

- 需要验证 target.h 中的偏移
- 需要验证帧大小
- 需要验证 mm_struct 大小

## 前置条件

- 服务器访问权限 (SSH key: /Users/xiuxiu391/Downloads/11.pem)
- 服务器上有编译好的 vmlinux

## 步骤

### 1. 连接服务器

```bash
ssh -i /Users/xiuxiu391/Downloads/11.pem -o ConnectTimeout=30 ubuntu@43.139.246.47
```

### 2. 验证帧大小 (objdump)

```bash
cd ~/android_kernel_oppo_sm8475-oppo-sm8475_b_16.0.0_find_n2

# 查找函数地址
nm vmlinux | grep -E "do_futex|sys_futex|futex_wait_requeue_pi"

# 反汇编查看帧大小
aarch64-linux-gnu-objdump -d --start-address=0x... --stop-address=0x... vmlinux | head -20
```

### 3. 验证 mm_struct (pahole)

```bash
pahole -C mm_struct vmlinux | tail -10
```

### 4. 验证 SLUB order

```bash
grep "CONFIG_NR_CPUS" .config
python3 -c "
mm_struct_sz = 960  # 从 pahole
nr_cpus = 32        # 从 config
fls_val = nr_cpus.bit_length()
min_objects = 4 * (fls_val + 1)
for order in range(5):
    slab = 4096 * (1 << order)
    objs = slab // mm_struct_sz
    if objs >= min_objects:
        print(f'Order {order}: {slab}B, {objs} objects')
        break
"
```

### 5. 更新 target.h

```bash
# 在本地编辑 exploit/targets/oppo-find_n2/target.h
```

## 帧大小参考

| 函数 | 帧大小 | 来源 |
|------|--------|------|
| __arm64_sys_futex | 0x70 (112B) | objdump |
| do_futex | 0x130 (304B) | objdump |
| futex_wait_requeue_pi | 0x1a0 (416B) | objdump |
| waiter 位置 | stack_top - 0x2c8 | 计算 |

## 注意事项

- 必须使用 OPPO 内核源码编译的 vmlinux
- 服务器 vmlinux 帧大小可能与设备不匹配
- pahole 需要 DWARF 调试信息
