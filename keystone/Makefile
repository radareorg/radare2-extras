include build.mk

PLUGINS=arm x86 mips sparc ppc hexagon sysz

LIBS=$(addsuffix _ks.$(SO_EXT),$(addprefix asm_,${PLUGINS}))
#R2PM_PLUGDIR?=${LIBDIR}/radare2/last/
R2PM_PLUGDIR?=~/.config/radare2/plugins

.PHONY: all clean install uninstall mrproper test

all: $(PLUGINS)

#$(info $(LIBS))

define kscc
$(CXX) -fPIC $(LDFLAGS_SHARED) -Wall\
	$(R2_CFLAGS) $(R2_LDFLAGS)\
	$(KS_CFLAGS) $(KS_LDFLAGS)\
	-o asm_$(1)_ks.$(SO_EXT) asm_$(1)_ks.c $(KS_LINK)
endef

define ksmake
asm_$(1)_ks.$(SO_EXT): asm_$(1)_ks.c keystone.c
	$$(call kscc,$(1))
endef

$(foreach lib,$(PLUGINS),$(eval $(call ksmake,$(lib))))

$(PLUGINS):
	$(MAKE) asm_$@_ks.$(SO_EXT)

install:
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(R2PM_PLUGDIR);)

uninstall:
	rm -rf $(R2PM_PLUGDIR)/*_ks.*

test:
	sh suite.sh

clean:
	rm -f *.$(SO_EXT)

mrproper: clean
	rm -f config.mk
