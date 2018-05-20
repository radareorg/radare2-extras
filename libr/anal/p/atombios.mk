OBJ_ATOMBIOS=anal_atombios.o
OBJ_ATOMBIOS+=../../asm/arch/atombios/atombios.o

STATIC_OBJ+=${OBJ_ATOMBIOS}
TARGET_ATOMBIOS=anal_atombios.${LIBEXT}

ALL_TARGETS+=${TARGET_ATOMBIOS}

${TARGET_ATOMBIOS}: ${OBJ_ATOMBIOS}
	${CC} -g $(call libname,anal_atombios) ${LDFLAGS} ${CFLAGS} -o anal_atombios.${LIBEXT} ${OBJ_ATOMBIOS}
