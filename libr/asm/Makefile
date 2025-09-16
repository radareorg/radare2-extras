R2PM_PLUGDIR ?=$(HOME)/.config/radare2/plugins

all:
	@echo

atombios:
	cd p ; $(MAKE) asm_atombios.$(LIBEXT)

spc700:
	cd p ; $(MAKE) asm_spc700.$(LIBEXT)

ba2:
	cd p ; $(MAKE) asm_ba2.$(LIBEXT)

blackfin:
	cd p ; $(MAKE) asm_blackfin.$(LIBEXT)

bea:
	cd p ; $(MAKE) asm_x86_bea.$(LIBEXT)

msil:
	cd p ; $(MAKE) asm_msil.$(LIBEXT)

x86_udis udis udis86:
	cd p ; $(MAKE) asm_x86_udis.$(LIBEXT)

udis86-clean:
	rm -rf p/asm_x86_udis.$(LIBEXT)*

tab:
	cd p ; $(MAKE) asm_x86_tab.$(LIBEXT)

swf:
	cd p ; $(MAKE) asm_swf.$(LIBEXT)

olly:
	cd p ; $(MAKE) asm_x86_olly.$(LIBEXT)

m68k_net:
	$(MAKE) -C p asm_m68k_net.$(LIBEXT)

zyan:
	$(MAKE) -C p asm_x86_zyan.$(LIBEXT)

zyan-install: zyan
	mkdir -p $(R2PM_PLUGDIR)
	cp -f p/asm_x86_zyan.$(LIBEXT) $(R2PM_PLUGDIR)

zyan-uninstall:
	$(RM) $(R2PM_PLUGDIR)/asm_x86_zyan.$(LIBEXT)
	
clean:
	rm -f p/*.$(LIBEXT) p/*.o

include ../../options.mk
