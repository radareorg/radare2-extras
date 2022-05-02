OBJ_BA2=anal_ba2.o

STATIC_OBJ+=${OBJ_BA2}
TARGET_BA2=anal_ba2.${LIBEXT}

ALL_TARGETS+=${TARGET_BA2}

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,anal_ba2) ${LDFLAGS} ${CFLAGS} -I../asm/arch/ba2 -o ${TARGET_BA2} ${OBJ_BA2}
