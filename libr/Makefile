all:

bea:
	$(MAKE) -C asm bea
	$(MAKE) -C anal bea

tab:
	$(MAKE) -C asm tab

m68k:
	$(MAKE) -C asm m68k
	$(MAKE) -C anal m68k

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C anal clean

bea-install:
	cp -f asm/p/asm_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)

tab-install:
	cp -f asm/p/asm_x86_tab.$(LIBEXT) $(R2PM_PLUGDIR)

m68k-install:
	cp -f asm/p/asm_m68k.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_m68k.$(LIBEXT) $(R2PM_PLUGDIR)

include ../options.mk
