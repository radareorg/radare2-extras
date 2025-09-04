OBJ_MSIL=arch_msil.o
#OBJ_MSIL+=../arch/msil/demsil.o

STATIC_OBJ+=${OBJ_MSIL}
TARGET_MSIL=arch_msil.${LIBEXT}

ALL_TARGETS+=${TARGET_MSIL}

$(OBJ_MSIL): %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

${TARGET_MSIL}: ${OBJ_MSIL}
	${CC} $(call libname,arch_msil) ${LDFLAGS} ${CFLAGS} -o ${TARGET_MSIL} ${OBJ_MSIL}
