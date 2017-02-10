include ../options.mk

LIBDWARFPATH=../../libdwarf-code/
LIBDWARFLIB=${LIBDWARFPATH}/libdwarf/
EXTRA_TARGETS+=${LIBDWARFLIB}/libdwarf.a -lelf -lz

CFLAGS+=$(shell pkg-config --cflags r_util)
CFLAGS+=-I${LIBDWARFLIB}

CC_COR=$(CC) -shared $(CFLAGS) -fPIC
CC_LIB=$(LDFLAGS) $(shell pkg-config --libs r_core) $(EXTRA_TARGETS)

all:
	$(CC_COR) -O2 -o dparser.$(LIBEXT) main.c $(CC_LIB)

install:
	cp -f *.$(LIBEXT) $(R2PM_PLUGDIR)

uninstall:
	for a in *.$(LIBEXT) ; do rm -f $(R2PM_PLUGDIR)/$$a ; done

clean:
	rm -f *.$(LIBEXT)
