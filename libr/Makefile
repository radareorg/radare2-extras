all:

bea:
	$(MAKE) -C asm bea
	$(MAKE) -C anal bea

atombios:
	$(MAKE) -C asm atombios
	$(MAKE) -C anal atombios
	$(MAKE) -C bin atombios

ba2:
	$(MAKE) -C asm ba2	
	$(MAKE) -C anal ba2

blackfin:
	$(MAKE) -C asm blackfin

tab:
	$(MAKE) -C asm tab

olly:
	$(MAKE) -C asm olly

udis udis86:
	$(MAKE) -C asm x86_udis
	$(MAKE) -C anal x86_udis

m68k:
	$(MAKE) -C asm m68k_net
	$(MAKE) -C anal m68k_net

zyan:
	$(MAKE) -C asm zyan

evm:
	$(MAKE) -C asm evm
	$(MAKE) -C anal evm
	$(MAKE) -C io evm
	$(MAKE) -C debug evm

nios:
	$(MAKE) -C asm nios
	$(MAKE) -C anal nios

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C anal clean

atombios-install:
	cp -f asm/p/asm_atombios.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_atombios.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f bin/p/bin_atombios.$(LIBEXT) $(R2PM_PLUGDIR)

ba2-install:
	cp -f asm/p/asm_ba2.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_ba2.$(LIBEXT) $(R2PM_PLUGDIR)

bea-install:
	cp -f asm/p/asm_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_x86_bea.$(LIBEXT) $(R2PM_PLUGDIR)

udis86-install udis-install:
	cp -f asm/p/asm_x86_udis.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_x86_udis.$(LIBEXT) $(R2PM_PLUGDIR)

tab-install:
	cp -f asm/p/asm_x86_tab.$(LIBEXT) $(R2PM_PLUGDIR)

olly-install:
	cp -f asm/p/asm_x86_olly.$(LIBEXT) $(R2PM_PLUGDIR)

m68k-install:
	cp -f asm/p/asm_m68k_net.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_m68k_net.$(LIBEXT) $(R2PM_PLUGDIR)

zyan-install:
	cp -f asm/p/asm_x86_zyan.$(LIBEXT) $(R2PM_PLUGDIR)

evm-install:
	cp -f asm/p/asm_evm.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_evm.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f io/p/io_evm.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f debug/p/debug_evm.$(LIBEXT) $(R2PM_PLUGDIR)

nios-install:
	cp -f asm/p/asm_nios.$(LIBEXT) $(R2PM_PLUGDIR)
	cp -f anal/p/anal_nios.$(LIBEXT) $(R2PM_PLUGDIR)

include ../options.mk
