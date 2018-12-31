R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
R2_INCLUDE_PATH=$(shell r2 -hh|grep INCDIR|awk '{print $$2}')
R2_LIB_PATH=$(shell r2 -hh|grep LIBDIR|awk '{print $$2}')
CFLAGS=-g -fPIC
CFLAGS+=-I$(R2_INCLUDE_PATH)
SUDO=sudo

LDFLAGS=-shared -L$(R2_LIB_PATH) -lr_util -lr_parse -lr_syscall

EXT_SO=$(shell r2 -hh|grep LIBEXT|awk '{print $$2}')

CC_ASM=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_asm)
CC_ANA=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_anal)
CC_BIN=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_bin) -lr_magic
CC_COR=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_core)

all:
	$(CC_ASM) -o asm_bpf.$(EXT_SO) asm_bpf.c
	$(CC_ANA) -o anal_bpf.$(EXT_SO) anal_bpf.c
	$(CC_BIN) -o bin_bpf.$(EXT_SO) bin_bpf.c
#	$(CC_COR) -o bpf_core.$(EXT_SO) bpf_core.c

install: all
	$(SUDO) cp -f *.$(EXT_SO) $(R2_PLUGIN_PATH)

uninstall:
	for a in *.$(EXT_SO) ; do rm -f $(R2_PLUGIN_PATH)/$$a ; done

clean:
	rm -f *.$(EXT_SO)
	rm -rf *.$(EXT_SO).dSYM
