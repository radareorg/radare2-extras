include ../options.mk

all:
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_baleful.$(EXT_SO) asm/asm_baleful.c
	$(CC) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_baleful.$(EXT_SO) anal/anal_baleful.c

install:
	cp -f asm/asm_baleful.$(EXT_SO) anal/anal_baleful.$(EXT_SO) \
		~/.config/radare2/plugins

uninstall:
	rm -f ~/.config/radare2/plugins/*baleful*
		
