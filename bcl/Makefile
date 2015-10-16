include ../options.mk

CFLAGS+=$(shell pkg-config --cflags r_util)
CC_ASM=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_asm)
CC_ANA=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_anal)
CC_BIN=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_bin)

all:
	$(CC_ASM) -o asm_bcl.$(EXT_SO) asm_bcl.c
	$(CC_ANA) -o anal_bcl.$(EXT_SO) anal_bcl.c
	$(CC_BIN) -o bin_bcl.$(EXT_SO) bin_bcl.c

install:
	cp -f *.$(EXT_SO) ~/.config/radare2/plugins

uninstall:
	for a in *.$(EXT_SO) ; do rm -f ~/.config/radare2/plugins/$$a ; done

clean:
	rm -f *.$(EXT_SO)
