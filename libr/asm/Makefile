D=$(HOME)/.config/radare2/plugins

bea:
	cd p ; $(MAKE) asm_x86_bea.$(LIBEXT)

msil:
	cd p ; $(MAKE) asm_msil.$(LIBEXT)

udis udis86:
	cd p ; $(MAKE) asm_x86_udis.$(LIBEXT)

tab:
	cd p ; $(MAKE) asm_x86_tab.$(LIBEXT)

swf:
	cd p ; $(MAKE) asm_swf.$(LIBEXT)

pyc:
	cd p ; $(MAKE) asm_pyc.$(LIBEXT)

olly:
	cd p ; $(MAKE) asm_x86_olly.$(LIBEXT)

m68k_net:
	$(MAKE) -C p asm_m68k_net.$(LIBEXT)

zyan:
	$(MAKE) -C p asm_x86_zyan.$(LIBEXT)

evm:
	$(MAKE) -C p asm_evm.$(LIBEXT)

zyan-install: zyan
	cp -f p/asm_x86_zyan.$(LIBEXT) $(D)

zyan-uninstall:
	$(RM) $(D)/asm_x86_zyan.$(LIBEXT)
	
clean:
	rm -f p/asm_x86_bea.$(LIBEXT)
	rm -f p/asm_x86_tab.$(LIBEXT)
	rm -f p/asm_x86_olly.$(LIBEXT)
	rm -f p/asm_m68k.$(LIBEXT)
	rm -f p/asm_x86_zyan.$(LIBEXT)

include ../../options.mk
