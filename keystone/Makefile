include build.mk

PLUGINS=arm x86 mips sparc ppc hexagon sysz

LIBS=$(addsuffix _ks.$(LIBEXT),$(addprefix asm_,${PLUGINS}))

.PHONY: all clean install uninstall mrproper test

all: $(PLUGINS)

#$(info $(LIBS))

define kscc
$(CC) $(LDFLAGS_SHARED) $(KS_LINK) -Wall\
	$(R2_CFLAGS) $(R2_LDFLAGS)\
	$(KS_CFLAGS) $(KS_LDFLAGS)\
	-o asm_$(1)_ks.$(LIBEXT) asm_$(1)_ks.c
endef

define ksmake
asm_$(1)_ks.$(LIBEXT): asm_$(1)_ks.c keystone.c
	$$(call kscc,$(1))
endef

$(foreach lib,$(PLUGINS),$(eval $(call ksmake,$(lib))))

$(PLUGINS):
	$(MAKE) asm_$@_ks.$(LIBEXT)

install:
	$(foreach lib,$(LIBS),$(INSTALL_LIB) $(lib) $(R2PM_PLUGDIR);)

uninstall:
	rm -f $(R2PM_PLUGDIR)/*_ks.*

test:
	sh suite.sh

clean:
	rm -f *.$(LIBEXT)

mrproper: clean
	rm -f config.mk
