OBJ_BA2=anal_ba2.o

STATIC_OBJ+=${OBJ_BA2}
TARGET_BA2=anal_ba2.${LIBEXT}

ALL_TARGETS+=${TARGET_BA2}

CFLAGS_BA2=$(R2_CFLAGS)
CFLAGS_BA2+=-I../../asm/arch/ba2
CFLAGS_BA2+=-Wall -shared -fPIC ${LDFLAGS_LIB}

$(OBJ_BA2): %.o : %.c
	$(CC) -c $(CFLAGS_BA2) $< -o $@

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,anal_ba2) ${LDFLAGS} ${CFLAGS_BA2} -o ${TARGET_BA2} ${OBJ_BA2}
