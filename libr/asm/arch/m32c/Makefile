R2HOME=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS+=$(shell pkg-config --cflags --libs r_asm r_util)
CFLAGS+=-I../include
EXT_SO=$(shell r2 -H R2_LIBEXT)

all:
	#make -C gnu |head -n 10
	$(CC) -shared -fPIC -o asm_m32c_gnu.$(EXT_SO) $(CFLAGS) asm_m32c_gnu.c gnu/*.o

install:
	cp *.$(EXT_SO) $(R2HOME)
