LIBEXT:=$(shell r2 -H LIBEXT)
USER_PLUGINS:=$(shell r2 -H USER_PLUGINS)
R2_CFLAGS:=$(shell pkg-config --cflags r_core)
R2_LDFLAGS:=$(shell pkg-config --libs r_core)

all: c-toxcore client r2tox.$(LIBEXT)

r2tox.$(LIBEXT): r2tox.c
	$(CC) -o r2tox.$(LIBEXT) -g -shared $(R2_CFLAGS) $(R2_LDFLAGS) -fPIC -I c-toxcore r2tox.c c-toxcore/libtoxcore.a -lsodium
	$(MAKE) install

client: client.c
	$(CC) -o client -g -I c-toxcore client.c c-toxcore/libtoxcore.a -lsodium

c-toxcore:
	git clone --depth=1 https://github.com/TokTok/c-toxcore
	cd c-toxcore ; cmake . ; make -j4

clean:
	rm -rf r2tox.$(LIBEXT)*
	rm -f client
	rm -rf client.dSYM
	rm -rf a.out*

install:
	cp -rf r2tox.$(LIBEXT)* $(USER_PLUGINS)

uninstall:
	rm -rf $(USER_PLUGINS)/r2tox.*

mrproper: clean
	rm -f tox.data
