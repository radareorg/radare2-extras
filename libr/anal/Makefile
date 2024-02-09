rl78:
	$(MAKE) -C p anal_rl78.$(LIBEXT)
	cp -f p/anal_rl78.$(LIBEXT) $(shell r2 -H R2_USER_PLUGINS)

ba2:
	cd p ; $(MAKE) anal_ba2.$(LIBEXT)

bea:
	cd p ; $(MAKE) anal_x86_bea.$(LIBEXT)

x86_udis udis udis86:
	cd p ; $(MAKE) anal_x86_udis.$(LIBEXT)

m68k_net:
	cd p ; $(MAKE) anal_m68k_net.$(LIBEXT)

atombios:
	cd p ; $(MAKE) anal_atombios.$(LIBEXT)

nios:
	cd p ; $(MAKE) anal_nios.$(LIBEXT)

clean:
	rm -f p/anal_ba2.$(LIBEXT)
	rm -f p/anal_x86_bea.$(LIBEXT)
	rm -f p/anal_m68k_net.$(LIBEXT)
	rm -f p/anal_atombios.{$(LIBEXT),o}
	rm -f p/anal_nios.$(LIBEXT)

include ../../options.mk
