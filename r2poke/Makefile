EXT_SO:=$(shell r2 -H R2_LIBEXT)
CFLAGS+=-Ipoke/libpoke
LDFLAGS+=poke/libpoke/.libs/libpoke.a
CFLAGS+=$(shell pkg-config --cflags bdw-gc)
LDFLAGS+=$(shell pkg-config --libs bdw-gc)
LDFLAGS+=$(shell pkg-config --cflags --libs r_core)

CFLAGS=-ggdb

all: poke
	$(CC) -shared -o core_poke.$(EXT_SO) $(CFLAGS) $(LDFLAGS) core_poke.c
	$(MAKE) user-install
	r2 -qc '""poke print("Hello World");' -

poke:
	@echo "Symlink or clone gnu poke in ${PWD}" || false
	git clone https://git.savannah.gnu.org/git/poke

user-install install:
	cp core_poke.$(EXT_SO) $(shell r2 -H R2_USER_PLUGINS)
