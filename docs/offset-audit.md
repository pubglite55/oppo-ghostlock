# 偏移审计报告 (output.elf)

**日期**: 2026-10-04
**对象**: `exploit/targets/oppo-find_n2/target.h`
**依据**: 工作区 `output.elf`(设备 boot image 经 vmlinux-to-elf 转换的产物)
**工具**: `analysis-scripts/audit_target_offsets.py`(纯 Python stdlib,不依赖 pyelftools/IDA/objdump)

---

## 1. 方法与镜像信息

`output.elf` 结构(实测):

| 段 | 地址 | 文件偏移 | 大小 |
|----|------|----------|------|
| `.kernel` | `0xffffffc008000000` | `0x1c0` | `0x2de2b3c` |
| `.bss` | `0xffffffc00ade2b3c` | `0x2de2cfc` | `0x1000000` |
| `.symtab` | — | `0x2de2cfc` | `0x349758` |

- `imagebase = KIMAGE_TEXT_BASE = 0xffffffc008000000`(与 `HANDOFF.md` 一致)
- `.symtab` 含 **143599** 个唯一符号名 → 可对 `target.h` 的每个 `*_OFF` 做精确地址比对
- 图像偏移 = `VA - KIMAGE_TEXT_BASE`

复现:

```bash
python analysis-scripts/audit_target_offsets.py \
    --elf output.elf --target exploit/targets/oppo-find_n2/target.h
```

---

## 2. 结论摘要

| 类别 | 结果 |
|------|------|
| 数据 / bss 符号偏移(16 个) | ✅ **全部正确**(精确相等) |
| 简单函数符号(`noop_llseek` 等) | ✅ 正确 |
| **ashmem 函数指针偏移(6 个)** | ❌ **原值整体错位一个函数** → 已修正 |
| `FOPS_*_OFF`(fops 表槽位) | ✅ 正确(与镜像表一致) |
| `docs/knowledge-notes.md` 的 fops 表 | ❌ 原值错误 → 已更正 |

修正后:`audit_target_offsets.py` 报告 **exact=22 / mismatch=0**。

---

## 3. 关键发现:ashmem 函数偏移整体错位一个函数

原 `target.h` 中每个 `ASHMEM_*_OFF` 指向的都是**名字前面那一个函数**。经 `.symtab` 复核:

| 宏 | 原值(错) | 实际指向 | 修正后 |
|----|----------|----------|--------|
| `ASHMEM_IOCTL_OFF` | `0x011ee6ec` | `ashmem_read_iter` | **`0x011ee7d0`** (`ashmem_ioctl`) |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x011ee7d0` | `ashmem_ioctl` | **`0x011ef2e0`** (`compat_ashmem_ioctl`) |
| `ASHMEM_MMAP_OFF` | `0x011ee7d0` | `ashmem_ioctl` | **`0x011ef340`** (`ashmem_mmap`) |
| `ASHMEM_OPEN_OFF` | `0x011ef340` | `ashmem_mmap` | **`0x011ef580`** (`ashmem_open`) |
| `ASHMEM_RELEASE_OFF` | `0x011ef580` | `ashmem_open` | **`0x011ef620`** (`ashmem_release`) |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x011ef620` | `ashmem_release` | **`0x011ef744`** (`ashmem_show_fdinfo`) |

另补两个此前缺失的符号:`ASHMEM_LLSEEK_OFF = 0x011ee5d4`、`ASHMEM_READ_ITER_OFF = 0x011ee6ec`。

**影响**:`put_fake_fops_table()`(`util.c`)/`refresh_fake_fops_text()`(`fops.c`)会把这些值写入 fake
`file_operations`。当前链路卡在更早的写原语,故此为**潜伏 bug**;一旦写原语打通,`open("/dev/ashmem")`
会跳进 `ashmem_mmap`、ioctl 会跳进 `ashmem_read_iter`,直接错乱。**现已修正。**

---

## 4. file_operations 表实测(本 build 与 mainline 5.10 不同)

dump `ashmem_fops`(VA `0xffffffc00a2c0048`)并按符号解析:

| 槽位 | 符号 | 对应 `FOPS_*_OFF` |
|------|------|-------------------|
| +0x08 | `ashmem_llseek.cfi_jt` | `FOPS_LLSEEK_OFF` |
| +0x20 | `ashmem_read_iter.cfi_jt` | `FOPS_READ_ITER_OFF` |
| +0x50 | `ashmem_ioctl.cfi_jt` | `FOPS_IOCTL_OFF` |
| +0x58 | `compat_ashmem_ioctl.cfi_jt` | `FOPS_COMPAT_IOCTL_OFF` |
| +0x60 | `ashmem_mmap.cfi_jt` | `FOPS_MMAP_OFF` |
| +0x70 | `ashmem_open.cfi_jt` | `FOPS_OPEN_OFF` |
| +0x80 | `ashmem_release.cfi_jt` | `FOPS_RELEASE_OFF` |
| +0xe0 | `ashmem_show_fdinfo.cfi_jt` | `FOPS_SHOW_FDINFO_OFF` |

**推论**:本 build 的 `struct file_operations` 中 `unlocked_ioctl` 位于 **+0x50**(mainline 5.10 为 +0x48),
自该字段起整体 **+8**。`target.h` 的 `FOPS_*_OFF` 与该实测布局一致(正确);
`docs/knowledge-notes.md` 原先的 `0x48/0x50/0x58/0x68/0x78/0xd8` 是错的,已按实测更正。

---

## 5. 数据符号比对明细(全部 OK)

```
ASHMEM_MISC_FOPS_OFF   0x022c0048  ashmem_fops
INIT_TASK_OFF          0x027cc000  init_task
INIT_UTS_NS_OFF        0x027cbda8  init_uts_ns
EMPTY_ZERO_PAGE_OFF    0x029c3000  empty_zero_page
ROOT_TASK_GROUP_OFF    0x029c8040  root_task_group
SELINUX_STATE_OFF      0x02a793c8  selinux_state
SECURITY_HOOK_HEADS_OFF 0x02302528 security_hook_heads
KMALLOC_CACHES_OFF     0x02302060  kmalloc_caches
ANON_PIPE_BUF_OPS_OFF  0x0216aa68  anon_pipe_buf_ops
INIT_NET_OFF           0x02924280  init_net
INIT_NSPROXY_OFF       0x027e0a80  init_nsproxy
SELINUX_BLOB_SIZES_OFF 0x02302bc0  selinux_blob_sizes
NOOP_LLSEEK_OFF        0x0056cf68  noop_llseek
SLIDE_NFULNL_LOGGER_OFF 0x027c14b8 nfulnl_logger
```

---

## 6. 未能验证的项

无对应 `.symtab` 符号(多为 `static`,需 IDA/反汇编才能确认):

- `SELINUX_ENFORCING_OFF` (`selinux_enforcing` 非独立符号;本内核 `enforcing` 应为 `selinux_state` 的字段,
  建议改为 `SELINUX_STATE + 字段偏移` 并在 IDA 确认)
- `CONFIGFS_READ_ITER_OFF` / `CONFIGFS_BIN_WRITE_ITER_OFF` / `COPY_SPLICE_READ_OFF`(非导出符号)
- `SLIDE_RANDOM_BOOT_ID_DATA_OFF`(`random_boot_id` static)

---

## 7. 附:本次一并处理的死代码

经调用图确认(仅 `common.h` 声明、活代码零调用):

- `exploit/src/slide.c` — pselect boot_id KASLR 泄漏,已被 PR #13 直接映射取代 → 移出构建
- `exploit/src/heap_spray.c` — 与 pipe physrw **循环依赖**,无法自举 → 移出构建
- `exploit/src/fops.c::do_pselect_fake_lock_route()` — 无调用者(及其唯一被调 `prepare_pselect_fdsets`)

三者均已加 `DEAD CODE` 文件头/函数头注记,并在 `exploit/Makefile` 的 `C_SRCS` 中注释排除(可逆)。