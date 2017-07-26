include ../lief.mk
include ../r2.mk

CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)
CFLAGS+=$(LIEF_CFLAGS)
LDFLAGS+=$(LIEF_LDFLAGS)

LDFLAGS+=-lc++

all: bin_pe_lief.$(SO_EXT)

bin_pe_lief.$(SO_EXT): bin_pe_lief.c
	$(CC) $(CFLAGS) bin_pe_lief.c $(LDFLAGS) -o $@
