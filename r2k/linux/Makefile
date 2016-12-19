ARCH_ARM := $(shell uname -m | grep -c "[arm|aarch]")

ifeq ($(ARCH_ARM),1)
	FOLDER := arm
else
	FOLDER := x86
endif

CFLAGS_r2kmod.o := -DDEBUG
obj-m += r2kmod.o
r2kmod-objs := r2k.o arch/$(FOLDER)/arch_functions.o arch/$(FOLDER)/dump_pagetables.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
