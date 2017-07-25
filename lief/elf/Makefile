include ../lief.mk
include ../r2.mk

CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)
CFLAGS+=$(LIEF_CFLAGS)
LDFLAGS+=$(LIEF_LDFLAGS)

LDFLAGS+=-lc++

all: bin_elf_lief.$(SO_EXT)

bin_elf_lief.$(SO_EXT): bin_elf_lief.c
	$(CC) $(CFLAGS) bin_elf_lief.c $(LDFLAGS) -o $@
