# ksu_min_load.ko —— 极简装载器（见 ksu_min_load.c 头部说明）
# 只需要 insmod 一句命令，所以用 -Os 压体积
obj-m += ksu_min_load.o
CFLAGS_ksu_min_load.o := -Os -fno-asynchronous-unwind-tables -fno-unwind-tables

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 clean
.PHONY: all clean
