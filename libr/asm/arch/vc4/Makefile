# Build the r2 vc4 asm/anal plugin straight from this directory.
# Mirrors libr/asm/p/vc4.mk + libr/plugs.mk but works standalone.

CC?=cc
VC4DIR=$(shell pwd)
PLUGDIR=$(abspath $(VC4DIR)/../../p)
PLUGSRC=$(PLUGDIR)/arch_vc4.c

R2_CFLAGS?=$(shell pkg-config --cflags r_arch r_asm r_util 2>/dev/null || pkg-config --cflags r_asm r_util 2>/dev/null || echo -I$(shell r2 -H R2_INCDIR 2>/dev/null))
R2_LDFLAGS?=$(shell pkg-config --libs r_arch r_asm r_util 2>/dev/null || pkg-config --libs r_asm r_util 2>/dev/null || echo -L$(shell r2 -H R2_LIBDIR 2>/dev/null) -lr_anal -lr_arch -lr_asm -lr_util)

R2HOME?=$(shell r2 -H R2_USER_PLUGINS 2>/dev/null || echo $(HOME)/.local/share/radare2/plugins)
UNAME_S?=$(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LIBEXT?=dylib
else
LIBEXT?=so
endif

TARGET=arch_vc4.$(LIBEXT)
PSEUDO=asm_vc4.$(LIBEXT)

CFLAGS+=$(R2_CFLAGS)
CFLAGS+=-g -O2 -Wall -fPIC
CFLAGS+=-I$(VC4DIR) -I$(VC4DIR)/include -I$(VC4DIR)/include/opcode
CFLAGS+=-I$(VC4DIR)/../include

LDFLAGS+=$(R2_LDFLAGS) -lr_anal
LDFLAGS+=-shared

OBJ=arch_vc4.o \
	vc4-dis.o vc4-asm.o vc4-desc.o vc4-ibld.o vc4-opc.o \
	cgen-bitset.o cgen-dis.o cgen-asm.o cgen-opc.o

all: $(TARGET) $(PSEUDO)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# binutils/cgen generated sources use the dashes in their names
vc4-%.o: vc4-%.c
	$(CC) -c $(CFLAGS) $< -o $@

# the r2 glue lives in libr/asm/p/
arch_vc4.o: $(PLUGSRC) vc4_anal.inc.c
	$(CC) -c $(CFLAGS) $(PLUGSRC) -o $@

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

$(PSEUDO): pseudo.o
	$(CC) -o $(PSEUDO) pseudo.o $(LDFLAGS)

install: $(TARGET) $(PSEUDO)
	mkdir -p $(R2HOME)
	cp -f $(TARGET) $(R2HOME)
	-codesign -f -s - $(R2HOME)/$(TARGET) 2>/dev/null || true

uninstall:
	rm -f $(R2HOME)/$(TARGET) $(R2HOME)/$(PSEUDO)

clean:
	rm -f $(OBJ) $(TARGET) pseudo.o $(PSEUDO)

mrproper: clean
	$(MAKE) -C libvc4 clean 2>/dev/null || true

.PHONY: all install uninstall clean mrproper
