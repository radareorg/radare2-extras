# webdev - expose the current r2 session to Chrome DevTools (CDP)

LIBEXT?=$(shell r2 -H R2_LIBEXT)
R2PM_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)

CFLAGS+=-fPIC -shared -g
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)

PLUGIN=core_webdev.$(LIBEXT)

all: $(PLUGIN)

$(PLUGIN): core_webdev.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

install user-install: all
	mkdir -p "$(R2PM_PLUGDIR)"
	rm -f "$(R2PM_PLUGDIR)/$(PLUGIN)"
	cp -f "$(PLUGIN)" "$(R2PM_PLUGDIR)"
	codesign -f -s - "$(R2PM_PLUGDIR)/$(PLUGIN)" 2>/dev/null || true

uninstall user-uninstall:
	rm -f "$(R2PM_PLUGDIR)/$(PLUGIN)"

clean:
	rm -f $(PLUGIN) *.o
	rm -rf $(PLUGIN).dSYM

.PHONY: all install user-install uninstall user-uninstall clean
