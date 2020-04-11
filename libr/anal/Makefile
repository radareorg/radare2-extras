bea:
	cd p ; $(MAKE) anal_x86_bea.$(LIBEXT)

x86_udis udis udis86:
	cd p ; $(MAKE) anal_x86_udis.$(LIBEXT)

m68k_net:
	cd p ; $(MAKE) anal_m68k_net.$(LIBEXT)

atombios:
	cd p ; $(MAKE) anal_atombios.$(LIBEXT)

evm:
	cd p ; $(MAKE) anal_evm.$(LIBEXT)

pyc:
	cd p ; $(MAKE) anal_pyc.$(LIBEXT)

clean:
	rm -f p/anal_x86_bea.$(LIBEXT)
	rm -f p/anal_m68k_net.$(LIBEXT)
	rm -f p/anal_atombios.{$(LIBEXT),o}
	rm -f p/anal_pyc.$(LIBEXT)

include ../../options.mk
