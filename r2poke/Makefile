EXT_SO:=$(shell r2 -H R2_LIBEXT)
LIBPOKE=poke/libpoke/.libs/libpoke.a
CFLAGS+=-Ipoke/libpoke
LDFLAGS+=$(LIBPOKE)
CFLAGS+=$(shell pkg-config --cflags bdw-gc)
LDFLAGS+=$(shell pkg-config --libs bdw-gc)
LDFLAGS+=$(shell pkg-config --cflags --libs r_core)
R2PM_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)

CFLAGS=-ggdb

all: $(LIBPOKE)
	$(CC) -shared -o core_poke.$(EXT_SO) $(CFLAGS) $(LDFLAGS) core_poke.c
	$(MAKE) user-install
	r2 -qc '""poke print("Hello World");' -

$(LIBPOKE): poke
	cd poke && ./bootstrap
	cd poke && ./configure --disable-option-checking '--prefix=NONE'  'CFLAGS=-I/opt/homebrew/Cellar/readline/8.2.1/include' 'LDFLAGS=-L/opt/homebrew/Cellar/readline/8.2.1/lib' 'PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@1.1/lib/pkgconfig' --cache-file=/dev/null --srcdir=.
	cd poke && $(MAKE) -j4

clean:
	rm -f core_poke.$(EXT_SO)

mrproper:
	rm -rf poke

poke:
	@echo "Symlink or clone gnu poke in ${PWD}" || false
	git clone https://git.savannah.gnu.org/git/poke

user-install install:
	cp -f core_poke.$(EXT_SO) $(R2PM_PLUGDIR)

user-uninstall uninstall:
	rm -f $(R2PM_PLUGDIR)/core_poke.$(EXT_SO)
