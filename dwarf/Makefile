include ../options.mk

LIBDWARFPATH=/home/panda/rsoc/p4n74/code/
LIBDWARFLIB=${LIBDWARFPATH}/libdwarf
EXTRA_TARGETS+=-L$(LIBDWARFPATH)/libdwarf -ldwarf

SDBPATH=/home/panda/rsoc/p4n74/sdb/src/
SDBLIB=${SDBPATH}/libsdb.a
EXTRA_TARGETS+=${SDBLIB}

CFLAGS+=$(shell pkg-config --cflags r_util)
CFLAGS+=-I${SDBPATH}/src  -I${LIBDWARFPATH}/libdwarf

LDFLAGS+=-lelf -lz
CC_LIB=$(CC)  -shared $(CFLAGS) $(LDFLAGS) -fPIC  # $(CFLAGS) $(LDFLAGS)
CC_COR=$(CC_LIB) $(shell pkg-config --libs r_core)

R2PM_PLUGDIR=/home/panda/.config/radare2/plugins/

all:
	$(CC_COR) -O2 -o dparser.$(LIBEXT) main.c $(EXTRA_TARGETS)

install:
	cp -f *.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	for a in *.$(LIBEXT) ; do rm -f $(R2PM_PLUGDIR)/$$a ; done

clean:
	rm -f *.$(LIBEXT)
