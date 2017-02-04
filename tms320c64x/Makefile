ifeq ($(shell uname),Darwin)
SO_EXT=dylib
else
SO_EXT=so
endif

R2PM_PLUGDIR?=$(shell r2 -H USER_PLUGINS)/plugins
CFLAGS+=-Icapstone/include
CFLAGS+=$(shell pkg-config --cflags r_asm)
LDFLAGS+=$(shell pkg-config --libs r_asm)
LIBFLAGS+=capstone/libcapstone.a
LIBFLAGS+=-shared -fPIC

all: capstone/libcapstone.a
	$(MAKE) anal_tms320c64x.$(SO_EXT)
	$(MAKE) asm_tms320c64x.$(SO_EXT)

anal_tms320c64x.$(SO_EXT): anal_tms320c64x.o
	$(CC) -o $@ $(LIBFLAGS) anal_tms320c64x.o $(shell pkg-config --libs r_anal)

asm_tms320c64x.$(SO_EXT): asm_tms320c64x.o
	$(CC) -o $@ asm_tms320c64x.o $(LIBFLAGS) $(shell pkg-config --libs r_asm)

capstone/libcapstone.a: capstone
	cp -f config.mk capstone
	$(MAKE) -j4 -C capstone

capstone:
	git clone --depth=1 -b next https://github.com/fotisl/capstone

install:
	cp -f *.$(SO_EXT) $(R2PM_PLUGDIR)

uninstall:
	rm -f $(R2PM_PLUGDIR)/*tms320*

clean:
	rm *.o *.$(SO_EXT)
