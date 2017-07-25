include lief.mk

USER_PLUGINS=$(shell r2 -HUSER_PLUGINS)

all: LIEF
	$(MAKE) -C elf
	$(MAKE) install
	r2 -F elf.lief hello-swift

LIEF:
	git clone --depth 1 https://github.com/lief-project/LIEF

install:
	mkdir -p $(USER_PLUGINS)
	cp -f elf/bin_elf_lief.$(SO_EXT) $(USER_PLUGINS)

uninstall:
