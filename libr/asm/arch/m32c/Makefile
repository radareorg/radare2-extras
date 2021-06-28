CFLAGS+=$(shell pkg-config --cflags --libs r_asm r_util)
CFLAGS+=-I../include

all:
	#make -C gnu |head -n 10
	$(CC) -shared -fPIC $(CFLAGS) asm_m32c_gnu.c gnu/*.o
