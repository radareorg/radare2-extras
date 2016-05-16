HOMEDEST?=~/.config/radare2/plugins

all:
	
bea:
	$(MAKE) -C asm bea
	$(MAKE) -C anal bea

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C anal clean

bea-install:
	mkdir -p $(HOMEDEST)
	cp -f asm/p/asm_x86_bea.$(LIBEXT) $(HOMEDEST)
	cp -f anal/p/anal_x86_bea.$(LIBEXT) $(HOMEDEST)
	
include ../options.mk
