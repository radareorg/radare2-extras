CARGO?=cargo
PKG_CONFIG?=pkg-config
LIBEXT?=$(shell r2 -H R2_LIBEXT)
LIBEXT:=$(if $(LIBEXT),$(LIBEXT),so)
R2PM_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)
R2_CFLAGS?=$(shell $(PKG_CONFIG) --cflags r_core)
R2_LIBS?=$(shell $(PKG_CONFIG) --libs r_core)
CFLAGS+=-Wall -Wextra -fPIC $(R2_CFLAGS)
RUSTLIB=target/release/libr2forwiroh.a
PLUGIN=core_r2forwiroh.$(LIBEXT)
RUST_SYSTEM_LIBS=-lpthread -ldl -lm
ifeq ($(shell uname -s),Darwin)
RUST_SYSTEM_LIBS=-framework Security -framework SystemConfiguration -framework CoreFoundation -liconv
endif

all: $(PLUGIN)

$(RUSTLIB): Cargo.toml Cargo.lock src/lib.rs
	$(CARGO) build --release --locked

$(PLUGIN): core_r2forwiroh.c sync.inc.c r2forwiroh.h $(RUSTLIB)
	$(CC) $(CFLAGS) -shared -o $@ core_r2forwiroh.c $(RUSTLIB) $(LDFLAGS) $(R2_LIBS) $(RUST_SYSTEM_LIBS)

install user-install: all
	test -n "$(R2PM_PLUGDIR)"
	mkdir -p "$(R2PM_PLUGDIR)"
	cp $(PLUGIN) "$(R2PM_PLUGDIR)/"

uninstall user-uninstall:
	test -n "$(R2PM_PLUGDIR)"
	rm -f "$(R2PM_PLUGDIR)/$(PLUGIN)"

test:
	$(CARGO) test --locked
	$(CC) $(CFLAGS) -o tests/test_sync tests/test_sync.c $(R2_LIBS)
	./tests/test_sync

clean:
	rm -f $(PLUGIN) tests/test_sync

.PHONY: all install user-install uninstall user-uninstall test clean
