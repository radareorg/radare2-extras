OBJ_X86_UDIS86=anal_x86_udis.o
OBJ_ESIL_UDIS86=esil_x86_udis.o
SHARED_X86_UDIS86=../../asm/arch/x86/udis86/decode.o
SHARED_X86_UDIS86+=../../asm/arch/x86/udis86/itab.o
SHARED_X86_UDIS86+=../../asm/arch/x86/udis86/syn-att.o
SHARED_X86_UDIS86+=../../asm/arch/x86/udis86/syn-intel.o
SHARED_X86_UDIS86+=../../asm/arch/x86/udis86/syn.o
SHARED_X86_UDIS86+=../../asm/arch/x86/udis86/udis86.o

SRC_X86_UDIS86=../../asm/arch/x86/udis86/*.c

EXT_SO=$(shell r2 -H LIBEXT)

STATIC_OBJ+=${OBJ_X86_UDIS86} ${OBJ_ESIL_UDIS86}
SHARED_OBJ+=${SHARED_X86_UDIS86}
TARGET_X86_UDIS86=anal_x86_udis.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_UDIS86}
CFLAGS+=-I../../asm/arch/x86 -I../../asm/arch/x86/udis86 -DHAVE_STRING_H=1

${TARGET_X86_UDIS86}: ${OBJ_X86_UDIS86} ${OBJ_ESIL_UDIS86}
	${CC} ${CFLAGS} ${LDFLAGS} $(call libname,anal_x86) -lr_reg -lr_anal -lr_util \
		$(SRC_X86_UDIS86) -o anal_x86_udis.${EXT_SO} ${OBJ_X86_UDIS86} ${OBJ_ESIL_UDIS86}
