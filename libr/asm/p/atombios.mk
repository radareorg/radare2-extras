OBJ_ATOMBIOS=arch_atombios.o
OBJ_ATOMBIOS+=../arch/atombios/atombios.o

TARGET_ATOMBIOS=arch_atombios.${LIBEXT}
STATIC_OBJ+=${OBJ_ATOMBIOS}

arch_atombios.o: arch_atombios.c
	$(CC) -c $(CFLAGS) $< -o $@

ALL_TARGETS+=${TARGET_ATOMBIOS}
${TARGET_ATOMBIOS}: ${OBJ_ATOMBIOS}
	${CC} -g $(call libname,arch_atombios) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ATOMBIOS} ${OBJ_ATOMBIOS}
