include build.mk

PLUGDIR=$(HOME)/.config/radare2/plugins

PLUGINS=arm x86 mips sparc ppc hexagon sysz

LIBS=$(addsuffix _ks.$(SO_EXT),$(addprefix asm_,${PLUGINS}))

.PHONY: all clean install uninstall mrproper test

all: $(PLUGINS)

#$(info $(LIBS))

define kscc
$(CXX) $(LDFLAGS_SHARED) $(KS_LINK) -Wall\
	$(R2_CFLAGS) $(R2_LDFLAGS)\
	$(KS_CFLAGS) $(KS_LDFLAGS)\
	-o asm_$(1)_ks.$(SO_EXT) asm_$(1)_ks.c
endef

define ksmake
asm_$(1)_ks.$(SO_EXT): asm_$(1)_ks.c keystone.c
	$$(call kscc,$(1))
endef

$(foreach lib,$(PLUGINS),$(eval $(call ksmake,$(lib))))

$(PLUGINS):
	$(MAKE) asm_$@_ks.$(SO_EXT)

install:
	mkdir -p $(PLUGDIR)
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(PLUGDIR);)

uninstall:
	rm -f $(PLUGDIR)/*_ks.*

test:
	sh suite.sh

clean:
	rm -f *.$(SO_EXT)

mrproper: clean
	rm -f config.mk
