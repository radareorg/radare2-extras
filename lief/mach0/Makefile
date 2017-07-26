include ../lief.mk
include ../r2.mk

CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)
CFLAGS+=$(LIEF_CFLAGS)
LDFLAGS+=$(LIEF_LDFLAGS)

LDFLAGS+=-lc++

all: bin_mach0_lief.$(SO_EXT)

bin_mach0_lief.$(SO_EXT): bin_mach0_lief.c
	$(CC) $(CFLAGS) bin_mach0_lief.c $(LDFLAGS) -o $@
