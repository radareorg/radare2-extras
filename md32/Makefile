R2 ?= r2
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
CC ?= cc
SO_EXT := $(shell $(R2) -H R2_LIBEXT)
PLUGIN = arch_md32.$(SO_EXT)
ASM_PLUGIN = asm_md32.$(SO_EXT)
R2_PLUGIN_PATH ?= $(shell $(R2) -H R2_USER_PLUGINS)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags r_arch)
CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -O2
LDLIBS += $(shell $(PKG_CONFIG) --libs r_arch)

all: $(PLUGIN) $(ASM_PLUGIN) tools/md32-run

$(PLUGIN): arch_md32.c md32_opcodes.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -o $@ arch_md32.c $(LDLIBS)

$(ASM_PLUGIN): asm_md32.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -o $@ asm_md32.c $(shell $(PKG_CONFIG) --libs r_asm)

install: $(PLUGIN) $(ASM_PLUGIN) tools/md32-run
	mkdir -p "$(DESTDIR)$(R2_PLUGIN_PATH)"
	cp -f $(PLUGIN) $(ASM_PLUGIN) "$(DESTDIR)$(R2_PLUGIN_PATH)/"

uninstall:
	rm -f "$(DESTDIR)$(R2_PLUGIN_PATH)/$(PLUGIN)"
	rm -f "$(DESTDIR)$(R2_PLUGIN_PATH)/$(ASM_PLUGIN)"

tools/md32-run: tools/md32-run.c arch_md32.c md32_opcodes.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tools/md32-run.c $(shell $(PKG_CONFIG) --libs r_anal)

test/test_md32: test/test_md32.c arch_md32.c md32_opcodes.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ test/test_md32.c $(LDLIBS)

test/test_parse: test/test_parse.c asm_md32.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ test/test_parse.c $(shell $(PKG_CONFIG) --libs r_asm)

test: $(PLUGIN) $(ASM_PLUGIN) tools/md32-run test/test_md32 test/test_parse
	./test/test_md32
	./test/test_parse
	$(PYTHON) test/test_plugin.py
	$(PYTHON) test/test_emulator.py
	$(PYTHON) test/test_firmware.py

clean:
	rm -f arch_md32.so arch_md32.dylib asm_md32.so asm_md32.dylib test/test_md32 test/test_parse tools/md32-run

.PHONY: all install uninstall test clean
