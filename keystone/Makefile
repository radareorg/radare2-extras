include build.mk

PLUGINS=arm x86 mips sparc ppc hexagon sysz

LIBS=$(addsuffix _ks.$(SO_EXT),$(addprefix asm_,${PLUGINS}))
#RZPM_PLUGDIR?=${LIBDIR}/radare2/last/
RZPM_PLUGDIR?=~/.config/rizin/plugins
RZPM_PREFIX?=~/.config/rizin/prefix

ifeq ($(shell uname),Darwin)
KS_LDFLAGS+=-Xlinker -rpath -Xlinker $(RZPM_PREFIX)/lib
endif
ifeq ($(shell uname),Linux)
KS_LDFLAGS+=-Wl,-R$(RZPM_PREFIX)/lib
endif

.PHONY: all clean install uninstall mrproper test

all: $(PLUGINS)

#$(info $(LIBS))

define kscc
$(CC) -c -fPIC -Wall\
	$(RZ_CFLAGS) $(KS_CFLAGS)\
	-o asm_$(1)_ks.$(O_EXT) asm_$(1)_ks.c
$(CXX) $(LDFLAGS_SHARED)\
	$(RZ_LDFLAGS) $(KS_LDFLAGS)\
	-o asm_$(1)_ks.$(SO_EXT) asm_$(1)_ks.$(O_EXT) $(KS_LINK)
rm asm_$(1)_ks.$(O_EXT)
endef

define ksmake
asm_$(1)_ks.$(SO_EXT): asm_$(1)_ks.c keystone.c
	$$(call kscc,$(1))
endef

$(foreach lib,$(PLUGINS),$(eval $(call ksmake,$(lib))))

$(PLUGINS):
	$(MAKE) asm_$@_ks.$(SO_EXT)

install:
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(RZPM_PLUGDIR);)

uninstall:
	rm -rf $(RZPM_PLUGDIR)/*_ks.*

test:
	sh suite.sh

clean:
	rm -f *.$(SO_EXT)

mrproper: clean
	rm -f config.mk
