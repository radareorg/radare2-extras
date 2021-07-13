R2HOME=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS+=$(shell pkg-config --cflags --libs r_asm r_util)
CFLAGS+=-I../include
EXT_SO=$(shell r2 -H R2_LIBEXT)

all:
	make -C gnu
	$(CC) -shared -fPIC -o asm_m32c_gnu.$(EXT_SO) $(CFLAGS) asm_m32c_gnu.c gnu/*.o
	$(CC) -shared -fPIC -o anal_m32c_gnu.$(EXT_SO) $(CFLAGS) anal_m32c_gnu.c gnu/*.o
	$(MAKE) install

test:
	r2 -a m32c.gnu -b32 -c 'wos 1 0xff 1' -c 'pd 4' -

install:
	cp *.$(EXT_SO) $(R2HOME)
