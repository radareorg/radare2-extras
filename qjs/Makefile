R2 ?= r2
PKG_CONFIG ?= pkg-config
QJS_REPO ?= https://github.com/quickjs-ng/quickjs.git
QJS_REF ?= HEAD
ifeq ($(origin QJS_DIR),undefined)
QJS_DIR = $(CURDIR)/.quickjs
QJS_MANAGED = 1
endif
QJS_CFLAGS ?=
QJS_LIBS ?= -lm -lpthread
SOEXT ?= $(shell $(R2) -H R2_LIBEXT)
PLUGDIR ?= $(shell $(R2) -H R2_USER_PLUGINS)
GLOBAL_PLUGDIR ?= $(shell $(R2) -H R2_LIBR_PLUGINS)
CFLAGS ?= -O2 -g
CFLAGS += -fPIC -fvisibility=hidden
CPPFLAGS += -I$(QJS_DIR) -D_GNU_SOURCE -DCONFIG_VERSION='"r2-qjs"' $(QJS_CFLAGS)
R2_CFLAGS = $(shell $(PKG_CONFIG) --cflags r_arch r_asm r_bin)
R2_LIBS = $(shell $(PKG_CONFIG) --libs r_arch r_asm r_bin)
QJS_SOURCES ?= $(wildcard $(QJS_DIR)/libregexp.c $(QJS_DIR)/libunicode.c $(QJS_DIR)/cutils.c $(QJS_DIR)/dtoa.c $(QJS_DIR)/libbf.c)
SHARED = -shared
ifeq ($(shell uname -s),Darwin)
SHARED = -dynamiclib
endif
PLUGINS = arch_qjs.$(SOEXT) parse_qjs_pseudo.$(SOEXT) bin_qjs.$(SOEXT)

.PHONY: all vm install user-install uninstall user-uninstall clean
all: vm
	$(CC) $(CPPFLAGS) $(CFLAGS) $(R2_CFLAGS) $(SHARED) -o arch_qjs.$(SOEXT) arch_qjs.c $(LDFLAGS) $(R2_LIBS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(R2_CFLAGS) $(SHARED) -o parse_qjs_pseudo.$(SOEXT) pseudo_qjs.c $(LDFLAGS) $(R2_LIBS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(R2_CFLAGS) $(SHARED) -o bin_qjs.$(SOEXT) bin_qjs.c $(QJS_SOURCES) $(LDFLAGS) $(R2_LIBS) $(QJS_LIBS)

vm:
ifeq ($(QJS_MANAGED),1)
	@test -d "$(QJS_DIR)/.git" || git clone "$(QJS_REPO)" "$(QJS_DIR)"
	git -C "$(QJS_DIR)" remote set-url origin "$(QJS_REPO)"
	git -C "$(QJS_DIR)" fetch --depth=1 origin "$(QJS_REF)"
	git -C "$(QJS_DIR)" checkout --detach FETCH_HEAD
endif
	@test -f "$(QJS_DIR)/quickjs.c" || { echo 'QJS_DIR must contain the selected QuickJS sources'; exit 1; }

user-install: all
	mkdir -p "$(DESTDIR)$(PLUGDIR)"
	cp $(PLUGINS) "$(DESTDIR)$(PLUGDIR)/"

install: PLUGDIR=$(GLOBAL_PLUGDIR)
install: user-install

user-uninstall:
	rm -f "$(DESTDIR)$(PLUGDIR)/arch_qjs.$(SOEXT)" "$(DESTDIR)$(PLUGDIR)/parse_qjs_pseudo.$(SOEXT)" "$(DESTDIR)$(PLUGDIR)/bin_qjs.$(SOEXT)"

uninstall: PLUGDIR=$(GLOBAL_PLUGDIR)
uninstall: user-uninstall

clean:
	rm -f $(PLUGINS)
