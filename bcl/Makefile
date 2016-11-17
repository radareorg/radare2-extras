include ../options.mk

CFLAGS+=$(shell pkg-config --cflags r_util)
CC_LIB=$(CC) -shared $(CFLAGS) $(LDFLAGS) -fPIC
CC_ASM=$(CC_LIB) $(shell pkg-config --libs r_asm)
CC_ANA=$(CC_LIB) $(shell pkg-config --libs r_anal)
CC_BIN=$(CC_LIB) $(shell pkg-config --libs r_bin)
CC_COR=$(CC_LIB) $(shell pkg-config --libs r_core)

all:
	$(CC_ASM) -o asm_bcl.$(LIBEXT) asm_bcl.c
	$(CC_ANA) -o anal_bcl.$(LIBEXT) anal_bcl.c
	$(CC_BIN) -o bin_bcl.$(LIBEXT) bin_bcl.c
	$(CC_COR) -o core_bcl.$(LIBEXT) core_bcl.c

install:
	cp -f *.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	for a in *.$(LIBEXT) ; do rm -f $(R2PM_PLUGDIR)/$$a ; done

clean:
	rm -f *.$(LIBEXT)
