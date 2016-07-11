include ../options.mk

CFLAGS+=$(R2_CFLAGS)
LDLAGS+=$(R2_LDFLAGS)

CFLAGS+=-Wall -shared -fPIC $(LDFLAGS_LIB)
CFLAGS+=-DLIL_ENDIAN=1

LDFLAGS+=$(LINK) -lr_util
DESTDIR?=

CURDIR=

TARGET_ASM=asm_agc.$(LIBEXT)
TARGET_ANAL=anal_agc.$(LIBEXT)

OBJ_ASM=
OBJ_ASM+=asm.o
OBJ_ASM+=asm_main.o

OBJ_ANAL=
OBJ_ANAL+=asm.o
OBJ_ANAL+=anal.o
OBJ_ANAL+=anal_main.o

ALL_TARGETS=
ALL_TARGETS+=$(TARGET_ASM)
ALL_TARGETS+=$(TARGET_ANAL)

all: $(ALL_TARGETS)

$(TARGET_ASM): $(OBJ_ASM)
	$(CC) $(call libname,asm_agc) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ASM) $(OBJ_ASM)

$(TARGET_ANAL): $(OBJ_ANAL)
	$(CC) $(call libname,anal_agc) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ANAL) $(OBJ_ANAL)

clean:
	rm -f *.{o,so}
