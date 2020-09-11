OBJ_ATOMBIOS=asm_atombios.o
OBJ_ATOMBIOS+=../arch/atombios/atombios.o

TARGET_ATOMBIOS=asm_atombios.${LIBEXT}
STATIC_OBJ+=${OBJ_ATOMBIOS}

ALL_TARGETS+=${TARGET_ATOMBIOS}
${TARGET_ATOMBIOS}: ${OBJ_ATOMBIOS}
	${CC} -g $(call libname,asm_atombios) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ATOMBIOS} ${OBJ_ATOMBIOS} -lr_util
