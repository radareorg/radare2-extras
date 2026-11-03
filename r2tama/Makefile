R2?=r2
PYTHON?=python3
PKG_CONFIG?=pkg-config
LIBEXT:=$(shell $(R2) -H R2_LIBEXT)
R2PM_PLUGDIR?=$(shell $(R2) -H R2_USER_PLUGINS)
PLUGIN=core_tama.$(LIBEXT)
SOURCES=core_tama.c input.inc.c audio.inc.c screen.inc.c icons.inc.c
CPPFLAGS+=$(shell $(PKG_CONFIG) --cflags r_core)
CFLAGS?=-O2 -g
CFLAGS+=-Wall -fPIC
LDLIBS+=$(shell $(PKG_CONFIG) --libs r_core)

all: $(PLUGIN)

$(PLUGIN): $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared core_tama.c -o $@ $(LDFLAGS) $(LDLIBS)

tests/test_core_tama: tests/test_core_tama.c $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core_tama.c -o $@ $(LDFLAGS) $(LDLIBS)

test: $(PLUGIN) tests/test_core_tama
	./tests/test_core_tama

test-rom: $(PLUGIN) tests/test_core_tama
	./tests/test_core_tama roms/p1.bin roms/p2.bin

test-rom-long: $(PLUGIN) tests/test_core_tama
	R2TAMA_LONG_SECONDS=600 ./tests/test_core_tama roms/p1.bin roms/p2.bin

test-visual: $(PLUGIN)
	R2="$(R2)" $(PYTHON) tests/test-visual.py
	R2="$(R2)" $(PYTHON) tests/test-quit.py

roms:
	$(PYTHON) scripts/fetch-roms.py

install user-install: $(PLUGIN)
	mkdir -p "$(DESTDIR)$(R2PM_PLUGDIR)"
	cp $(PLUGIN) "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

uninstall user-uninstall:
	rm -f "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

clean:
	rm -f $(PLUGIN) tests/test_core_tama

.PHONY: all test test-rom test-rom-long test-visual roms install user-install uninstall user-uninstall clean
