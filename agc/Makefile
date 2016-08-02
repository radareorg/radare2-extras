include ../options.mk

CFLAGS+=$(R2_CFLAGS) -Wall -shared -fPIC $(LDFLAGS_LIB) -DLIL_ENDIAN=1
LDLAGS+=$(R2_LDFLAGS)

LDFLAGS+=$(LINK) -lr_util
DESTDIR?=

CURDIR=

TARGET_ASM=asm_agc.$(LIBEXT)
TARGET_ANAL=anal_agc.$(LIBEXT)

OBJ_ASM=asm.o asm_main.o

OBJ_ANAL=asm.o anal.o anal_main.o

ALL_TARGETS= $(TARGET_ASM) $(TARGET_ANAL)

all: $(ALL_TARGETS)

$(TARGET_ASM): $(OBJ_ASM)
	$(CC) $(call libname,asm_agc) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ASM) $(OBJ_ASM)

$(TARGET_ANAL): $(OBJ_ANAL)
	$(CC) $(call libname,anal_agc) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ANAL) $(OBJ_ANAL)

clean:
	rm -f *.{o,so}
