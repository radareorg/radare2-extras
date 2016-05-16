include ../options.mk

R2PM_PLUGDIR=~/.config/radare2/plugins
R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared

all: asm/asm_baleful.$(LIBEXT) anal/anal_baleful.$(LIBEXT)

asm/asm_baleful.$(LIBEXT):
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_baleful.$(LIBEXT) asm/asm_baleful.c

anal/anal_baleful.$(LIBEXT):
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_baleful.$(LIBEXT) anal/anal_baleful.c

clean:
	rm -f */*.$(LIBEXT)

install:
	cp -f asm/asm_baleful.$(LIBEXT) anal/anal_baleful.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	rm -f ${R2PM_PLUGDIR}/*baleful*
