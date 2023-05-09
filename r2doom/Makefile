CFLAGS+=$(shell pkg-config --cflags --libs r_cons r_util)

BINDIR=$(shell r2pm -H R2PM_BINDIR)

all:
	$(CC) -o r2doom -g doom.c entities.c $(CFLAGS)

install:
	mkdir -p ${BINDIR}
	cp -f r2doom ${BINDIR}/r2doom

uninstall:
	rm -f ${BINDIR}/r2doom
