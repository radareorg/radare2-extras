R2 ?= r2
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
CC ?= cc
SO_EXT := $(shell $(R2) -H R2_LIBEXT)
PLUGIN = arch_mn103.$(SO_EXT)
ASM_PLUGIN = asm_mn103.$(SO_EXT)
# r2pm passes R2PM_PLUGDIR; otherwise the user plugin directory
R2_PLUGIN_PATH ?= $(if $(R2PM_PLUGDIR),$(R2PM_PLUGDIR),$(shell $(R2) -H R2_USER_PLUGINS))
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags r_arch)
CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -O2
LDLIBS += $(shell $(PKG_CONFIG) --libs r_arch)

DECODER = mn103_decode.c mn103_decode.h mn103_opcodes.h

all: $(PLUGIN) $(ASM_PLUGIN)

$(PLUGIN): arch_mn103.c $(DECODER)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -o $@ arch_mn103.c $(LDLIBS)

$(ASM_PLUGIN): asm_mn103.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -o $@ asm_mn103.c $(shell $(PKG_CONFIG) --libs r_asm)

mn103_opcodes.h: isa/m10300-opc.c tools/gen_mn103_tables.py
	$(PYTHON) tools/gen_mn103_tables.py $< -o $@

install: $(PLUGIN) $(ASM_PLUGIN)
	mkdir -p "$(DESTDIR)$(R2_PLUGIN_PATH)"
	cp -f $(PLUGIN) $(ASM_PLUGIN) "$(DESTDIR)$(R2_PLUGIN_PATH)/"

uninstall:
	rm -f "$(DESTDIR)$(R2_PLUGIN_PATH)/$(PLUGIN)"
	rm -f "$(DESTDIR)$(R2_PLUGIN_PATH)/$(ASM_PLUGIN)"

test/test_mn103: test/test_mn103.c arch_mn103.c $(DECODER)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ test/test_mn103.c $(LDLIBS)

tools/mn103-dis: tools/mn103-dis.c $(DECODER)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tools/mn103-dis.c mn103_decode.c $(shell $(PKG_CONFIG) --libs r_util)

test: $(PLUGIN) $(ASM_PLUGIN) test/test_mn103 tools/mn103-dis
	./test/test_mn103
	$(PYTHON) test/test_plugin.py

clean:
	rm -f arch_mn103.so arch_mn103.dylib asm_mn103.so asm_mn103.dylib test/test_mn103 tools/mn103-dis

.PHONY: all install uninstall test clean
