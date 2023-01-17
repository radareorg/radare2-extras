R2HOME=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS+=$(shell pkg-config --cflags --libs r_asm r_util)
CFLAGS+=-I../include -fPIC
EXT_SO=$(shell r2 -H R2_LIBEXT)

all:
	make -C gnu
	$(CC) -shared -fPIC -o asm_m32c_gnu.$(EXT_SO) $(CFLAGS) asm_m32c_gnu.c gnu/*.o
	$(CC) -shared -fPIC -o anal_m32c_gnu.$(EXT_SO) $(CFLAGS) anal_m32c_gnu.c gnu/*.o
	$(MAKE) install
	$(MAKE) test

test:
	r2 -qcq -a m32c -b32 -c 'woe 1 0xff 1' -c 'pd 10' -

install:
	mkdir -p $(R2HOME)
	cp *.$(EXT_SO) $(R2HOME)
