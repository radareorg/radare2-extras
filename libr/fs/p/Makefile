PKG_CONFIG ?= pkg-config
R2 ?= r2
LIBEXT ?= $(shell $(R2) -H LIBEXT)
R2_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags r_fs)
R2_LIBS ?= $(shell $(PKG_CONFIG) --libs r_fs)

PLUGINS = fs_jffs2.$(LIBEXT) fs_squash.$(LIBEXT)

.PHONY: all check clean user-install install-squash
all: $(PLUGINS)

check: all
	R2="$(R2)" LIBEXT="$(LIBEXT)" python3 ../test/plugins.py

fs_jffs2.$(LIBEXT): fs_jffs2.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(R2_CFLAGS) -fPIC -shared $(LDFLAGS) -o $@ $< $(R2_LIBS) -lz

fs_squash.$(LIBEXT): fs_squash.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(R2_CFLAGS) $(shell $(PKG_CONFIG) --cflags liblzma) -fPIC -shared $(LDFLAGS) -o $@ $< $(R2_LIBS) -lz $(shell $(PKG_CONFIG) --libs liblzma)

R2PLUGDIR ?= $(shell $(R2) -H R2_USER_PLUGINS)
user-install: all
	mkdir -p "$(DESTDIR)$(R2PLUGDIR)"
	cp $(PLUGINS) "$(DESTDIR)$(R2PLUGDIR)/"

install-squash: fs_squash.$(LIBEXT)
	mkdir -p "$(DESTDIR)$(R2PLUGDIR)"
	cp $< "$(DESTDIR)$(R2PLUGDIR)/"

clean:
	rm -f $(PLUGINS)
