yara:
	cd yara/yara && ./configure --prefix=$(PREFIX) && $(MAKE)

yara-clean:
	$(MAKE) -C yara/yara clean

yara-install:
	$(MAKE) -C yara/yara install

yara-uninstall:
	$(MAKE) -C yara/yara uninstall

.PHONY: yara yara-clean yara-install
