all:

bea:
	$(MAKE) -C asm bea
	$(MAKE) -C anal bea

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C anal clean

bea-install:
	cp -f asm/p/asm_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)

include ../options.mk
