include ../options.mk

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
	cp -f asm/asm_baleful.$(EXT_SO) anal/anal_baleful.$(EXT_SO) \
		~/.config/radare2/plugins

uninstall:
	rm -f ~/.config/radare2/plugins/*baleful*
