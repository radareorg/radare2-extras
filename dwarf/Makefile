include ../options.mk

LIBDWARFPATH=../../libdwarf-code/
LIBDWARFLIB=${LIBDWARFPATH}/libdwarf
EXTRA_TARGETS+=-L$(LIBDWARFPATH)/libdwarf -ldwarf

SDBPATH=../../shlr/sdb/src/
SDBLIB=${SDBPATH}/libsdb.a
EXTRA_TARGETS+=${SDBLIB}

CFLAGS+=$(shell pkg-config --cflags r_util)
CFLAGS+=-I${SDBPATH}/src  -I${LIBDWARFPATH}/libdwarf

LDFLAGS+=-lelf -lz
CC_LIB=$(CC) -shared $(CFLAGS) $(LDFLAGS) -fPIC
CC_COR=$(CC_LIB) $(shell pkg-config --libs r_core)

all:
	$(CC_COR) -O2 -o dparser.$(LIBEXT) main.c $(EXTRA_TARGETS)

install:
	cp -f *.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	for a in *.$(LIBEXT) ; do rm -f $(R2PM_PLUGDIR)/$$a ; done

clean:
	rm -f *.$(LIBEXT)
