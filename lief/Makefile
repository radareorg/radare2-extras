include lief.mk

R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

all: LIEF
	$(MAKE) -C pe
	$(MAKE) -C elf
	$(MAKE) -C mach0
	$(MAKE) install
	#r2 -F elf.lief hello-swift
	#r2 -F mach0.lief /bin/ls

LIEF:
	git clone --depth 1 https://github.com/lief-project/LIEF
	cd LIEF && cmake . && $(MAKE) -j4

install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f elf/bin_elf_lief.$(SO_EXT) $(R2_USER_PLUGINS)
	cp -f mach0/bin_mach0_lief.$(SO_EXT) $(R2_USER_PLUGINS)
	cp -f pe/bin_pe_lief.$(SO_EXT) $(R2_USER_PLUGINS)

uninstall:
	rm -f $(R2_USER_PLUGINS)/bin_elf_lief.$(SO_EXT)
	rm -f $(R2_USER_PLUGINS)/mach0/bin_mach0_lief.$(SO_EXT)
	rm -f $(R2_USER_PLUGINS)/pe/bin_pe_lief.$(SO_EXT)

clean:
	rm -rf LIEF
