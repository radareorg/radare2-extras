include ../options.mk

R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared

all: asm/asm_baleful.$(LIBEXT) anal/anal_baleful.$(LIBEXT)

asm/asm_baleful.$(LIBEXT):
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_baleful.$(LIBEXT) asm/asm_baleful.c

anal/anal_baleful.$(LIBEXT):
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_baleful.$(LIBEXT) anal/anal_baleful.c

w32:
	$(MAKE) CC=i586-mingw32-gcc LDFLAGS=-L/tmp/radare2-w32-0.10.5 LIBEXT=dll

clean:
	rm -f */*.$(LIBEXT) */*.dll */*.so */*.dylib

install:
	cp -f asm/asm_baleful.$(LIBEXT) anal/anal_baleful.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	rm -f ${R2PM_PLUGDIR}/*baleful*
