CFLAGS+=$(shell pkg-config --cflags --libs r_cons r_util)
ifeq ($(shell uname),Linux)
CFLAGS+=-lm
endif

BINDIR=$(shell r2pm -H R2PM_BINDIR)

all:
	$(CC) -o r2doom -g $(CFLAGS) doom.c entities.c

install:
	mkdir -p ${BINDIR}
	cp -f r2doom ${BINDIR}/r2doom

uninstall:
	rm -f ${BINDIR}/r2doom
