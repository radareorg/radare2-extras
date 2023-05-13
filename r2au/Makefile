CFLAGS+=$(shell pkg-config --cflags r_util r_arch)
AO_CFLAGS+=$(shell pkg-config --cflags ao)
ifeq ($(AO_CFLAGS),)
error install libao
endif
CFLAGS+=$(AO_CFLAGS)
#CFLAGS+=-fsanitize=address
CFLAGS+=-g -fPIC 
LDFLAGS+=$(shell pkg-config --libs r_util r_io r_cons r_core)
LDFLAGS+=$(shell pkg-config --libs ao)
LDFLAGS+=-shared
ifeq ($(shell uname),Linux)
LDFLAGS+=-lm
endif
LIBEXT=$(shell r2 -H LIBEXT)
R2P=$(shell r2 -H R2_USER_PLUGINS)

LIBS=core_au.$(LIBEXT) arch_au.$(LIBEXT)

all: $(LIBS)

arch_au.$(LIBEXT): arch_au.c
	$(CC) $(CFLAGS) $(LDFLAGS) arch_au.c -o arch_au.$(LIBEXT)

#anal_au.$(LIBEXT): anal_au.c
#	$(CC) $(CFLAGS) $(LDFLAGS) anal_au.c -o anal_au.$(LIBEXT)

core_au.$(LIBEXT): core_au.c noise.c
	$(CC) $(CFLAGS) $(LDFLAGS) noise.c core_au.c -o core_au.$(LIBEXT)

user-install install:
	mkdir -p $(R2P)
	cp -rf arch_au.$(LIBEXT)* $(R2P)
	cp -rf core_au.$(LIBEXT)* $(R2P)

clean:
	rm -f $(LIBS)

test:
	r2 -a au -b 32 -i test.r2  malloc://1M

test2:
	r2 -c 'b 4K;aui;aup' -c auv malloc://64K

uninstall:
	rm $(R2P)/*au.$(LIBEXT)*

m:
	$(MAKE) all
	$(MAKE) install
	r2 -a au -b 32 malloc://1M
