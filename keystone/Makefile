include build.mk

PLUGINS=arm x86 mips sparc ppc hexagon s390x evm

LIBS=$(addsuffix _ks.$(SO_EXT),$(addprefix arch_,${PLUGINS}))
#R2PM_PLUGDIR?=${LIBDIR}/radare2/last/
R2PM_PLUGDIR?=~/.config/radare2/plugins
R2PM_PREFIX?=~/.config/radare2/prefix

ifeq ($(shell uname),Darwin)
KS_LDFLAGS+=-Xlinker -rpath -Xlinker $(R2PM_PREFIX)/lib
endif
ifeq ($(shell uname),Linux)
KS_LDFLAGS+=-Wl,-R$(R2PM_PREFIX)/lib
endif

.PHONY: all clean install uninstall mrproper test

all: $(PLUGINS)

#$(info $(LIBS))

define kscc
$(CC) -c -fPIC -Wall\
	$(R2_CFLAGS) $(KS_CFLAGS)\
	-o arch_$(1)_ks.$(O_EXT) arch_$(1)_ks.c
$(CXX) $(LDFLAGS_SHARED)\
	$(R2_LDFLAGS) $(KS_LDFLAGS)\
	-o arch_$(1)_ks.$(SO_EXT) arch_$(1)_ks.$(O_EXT) $(KS_LINK)
rm arch_$(1)_ks.$(O_EXT)
endef

define ksmake
arch_$(1)_ks.$(SO_EXT): arch_$(1)_ks.c keystone.c
	$$(call kscc,$(1))
endef

$(foreach lib,$(PLUGINS),$(eval $(call ksmake,$(lib))))

$(PLUGINS):
	$(MAKE) arch_$@_ks.$(SO_EXT)

install:
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(R2PM_PLUGDIR);)

user-install:
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(R2PM_PLUGDIR);)

user-uninstall uninstall:
	rm -rf $(R2PM_PLUGDIR)/*_ks.*

test:
	sh suite.sh

clean:
	rm -f *.$(SO_EXT)

mrproper: clean
	rm -f config.mk
