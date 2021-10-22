CFLAGS_UDIS=$(R2_CFLAGS)
CFLAGS_UDIS+=-g -I$(TOP)/shlr -I../arch/ -I../arch/include
CFLAGS_UDIS+=-Wall -shared -fPIC ${LDFLAGS_LIB}
CFLAGS_UDIS+=-I../arch/x86

OBJ_X86_UDIS86=asm_x86_udis.o
SRC_X86_UDIS86=../arch/x86/udis86/*.c

STATIC_OBJ+=${OBJ_X86_UDIS86}
TARGET_X86_UDIS86=asm_x86_udis.${LIBEXT}

ALL_TARGETS+=${TARGET_X86_UDIS86}

$(OBJ_X86_UDIS86): %.o : %.c
	$(CC) -c $(CFLAGS_UDIS) $< -o $@

${TARGET_X86_UDIS86}: ${OBJ_X86_UDIS86}
	${CC} $(call libname,asm_x86_udis) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_UDIS86} ${OBJ_X86_UDIS86} ${SRC_X86_UDIS86}
