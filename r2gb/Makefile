R2?=r2
R2R?=r2r
PYTHON?=python3
PKG_CONFIG?=pkg-config
LIBEXT:=$(shell $(R2) -H R2_LIBEXT)
R2PM_PLUGDIR?=$(shell $(R2) -H R2_USER_PLUGINS)
PLUGIN=core_gb.$(LIBEXT)
SOURCES=core_gb.c apu.inc.c input.inc.c instructions.inc.c registers.inc.c

CPPFLAGS+=$(shell $(PKG_CONFIG) --cflags r_core)
CFLAGS+=-g -Wall -fPIC
LDLIBS+=$(shell $(PKG_CONFIG) --libs r_core)

all: $(PLUGIN)

$(PLUGIN): $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared core_gb.c -o $@ $(LDFLAGS) $(LDLIBS)

tests/test_core_gb: tests/test_core_gb.c tests/minunit.h $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core_gb.c -o $@ $(LDFLAGS) $(LDLIBS) -lm

test: $(PLUGIN) tests/test_core_gb
	R2GB_PLUGIN="$(CURDIR)/$(PLUGIN)" ./tests/test_core_gb
	R2R_RADARE2="$(R2)" $(R2R) -u tests/db/gb_peripherals

test-visual: $(PLUGIN)
	R2="$(R2)" R2GB_PLUGIN="$(CURDIR)/$(PLUGIN)" $(PYTHON) tests/test-gameboy-visual.py

install user-install: $(PLUGIN)
	mkdir -p "$(DESTDIR)$(R2PM_PLUGDIR)"
	cp $(PLUGIN) "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

uninstall user-uninstall:
	rm -f "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

clean:
	rm -f $(PLUGIN) tests/test_core_gb

.PHONY: all test test-visual install user-install uninstall user-uninstall clean
