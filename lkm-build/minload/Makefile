# ksu_min_load.ko —— 极简装载器（见 ksu_min_load.c 头部说明）
# 只需要 insmod 一句命令，所以用 -Os 压体积
#
# ★ 交叉编译标志必须和主模块（build-lkm.sh 里那条）逐字一致：
#   ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
#   实测漏掉 LLVM_IAS=1 时，arm64 的内联汇编会被当 x86 编 ⇒
#     arch/arm64/include/asm/atomic_lse.h:369: error: unknown register name 'x0' in asm
obj-m += ksu_min_load.o
CFLAGS_ksu_min_load.o := -Os -fno-asynchronous-unwind-tables -fno-unwind-tables

KFLAGS := ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(KFLAGS) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(KFLAGS) clean
.PHONY: all clean
