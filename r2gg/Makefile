R2?=r2
PYTHON?=python3
PKG_CONFIG?=pkg-config
LIBEXT:=$(shell $(R2) -H R2_LIBEXT)
R2PM_PLUGDIR?=$(shell $(R2) -H R2_USER_PLUGINS)
PLUGIN=core_gg.$(LIBEXT)
SOURCES=core_gg.c input.inc.c instructions.inc.c registers.inc.c

CPPFLAGS+=$(shell $(PKG_CONFIG) --cflags r_core)
CFLAGS?=-O2 -g
CFLAGS+=-Wall -fPIC
LDLIBS+=$(shell $(PKG_CONFIG) --libs r_core)

all: $(PLUGIN)

$(PLUGIN): $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared core_gg.c -o $@ $(LDFLAGS) $(LDLIBS)

tests/test_core_gg: tests/test_core_gg.c $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core_gg.c -o $@ $(LDFLAGS) $(LDLIBS)

tests/test-columns: tests/test-columns.c $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test-columns.c -o $@ $(LDFLAGS) $(LDLIBS)

tests/test-sonic: tests/test-sonic.c $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test-sonic.c -o $@ $(LDFLAGS) $(LDLIBS)

test-sonic: tests/test-sonic
	./tests/test-sonic "$(ROM)" $(if $(WAV),"$(WAV)")

test-rom: tests/test-columns
	./tests/test-columns "$(ROM)" $(if $(SNAPSHOTS),"$(SNAPSHOTS)")

test-rom-long: tests/test-columns
	R2GG_ATTRACT_FRAMES=5000 ./tests/test-columns "$(ROM)"
	R2GG_GAME_FRAMES=5000 ./tests/test-columns "$(ROM)"

test: $(PLUGIN) tests/test_core_gg
	./tests/test_core_gg

test-speed: $(PLUGIN)
	R2="$(R2)" $(PYTHON) tests/test-visual-speed.py "$(ROM)"

test-visual: $(PLUGIN)
	R2="$(R2)" R2GG_PLUGIN="$(CURDIR)/$(PLUGIN)" $(PYTHON) tests/test-gamegear-visual.py

install user-install: $(PLUGIN)
	mkdir -p "$(DESTDIR)$(R2PM_PLUGDIR)"
	cp $(PLUGIN) "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

uninstall user-uninstall:
	rm -f "$(DESTDIR)$(R2PM_PLUGDIR)/$(PLUGIN)"

clean:
	rm -f $(PLUGIN) tests/test_core_gg tests/test-columns tests/test-sonic

.PHONY: all test test-visual test-rom test-rom-long test-sonic test-speed install user-install uninstall user-uninstall clean
