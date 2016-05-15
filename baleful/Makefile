include ../options.mk

R2PM_PLUGDIR=~/.config/radare2/plugins
R2_CFLAGS+=-fPIC
R2_LDFLAGS+=-shared

all: asm/asm_baleful.$(EXT_SO) anal/anal_baleful.$(EXT_SO)

asm/asm_baleful.$(EXT_SO):
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_baleful.$(EXT_SO) asm/asm_baleful.c

anal/anal_baleful.$(EXT_SO):
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_baleful.$(EXT_SO) anal/anal_baleful.c

clean:
	rm -f */*.$(EXT_SO)

install:
	cp -f asm/asm_baleful.$(EXT_SO) anal/anal_baleful.$(EXT_SO) $(R2PM_PLUGDIR)

uninstall:
	rm -f ${R2PM_PLUGDIR}/*baleful*
