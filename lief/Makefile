include lief.mk

USER_PLUGINS=$(shell r2 -HUSER_PLUGINS)

all: LIEF
	$(MAKE) -C pe
	$(MAKE) -C elf
	$(MAKE) -C mach0
	$(MAKE) install
	#r2 -F elf.lief hello-swift
	#r2 -F mach0.lief /bin/ls

LIEF:
	git clone --depth 1 https://github.com/lief-project/LIEF

install:
	mkdir -p $(USER_PLUGINS)
	cp -f elf/bin_elf_lief.$(SO_EXT) $(USER_PLUGINS)
	cp -f mach0/bin_mach0_lief.$(SO_EXT) $(USER_PLUGINS)
	cp -f pe/bin_pe_lief.$(SO_EXT) $(USER_PLUGINS)

uninstall:
	rm -f $(USER_PLUGINS)/bin_elf_lief.$(SO_EXT)
	rm -f $(USER_PLUGINS)/mach0/bin_mach0_lief.$(SO_EXT)
	rm -f $(USER_PLUGINS)/pe/bin_pe_lief.$(SO_EXT)
