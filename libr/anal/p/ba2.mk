OBJ_BA2=anal_ba2.o
CFLAGS+=-I../asm/arch/ba2

STATIC_OBJ+=${OBJ_BA2}
TARGET_BA2=anal_ba2.${LIBEXT}

ALL_TARGETS+=${TARGET_BA2}

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,anal_ba2) ${LDFLAGS} ${CFLAGS} -o ${TARGET_BA2} ${OBJ_BA2}
