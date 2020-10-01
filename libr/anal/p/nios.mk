OBJ_NIOS=anal_nios.o

STATIC_OBJ+=${OBJ_NIOS}
TARGET_NIOS=anal_nios.${LIBEXT}

ALL_TARGETS+=${TARGET_NIOS}

CFLAGS+=-I../../asm/arch
CFLAGS+=-I../../asm/arch/include

${TARGET_NIOS}: ${OBJ_NIOS}
	${CC} $(call libname,anal_nios) ${LDFLAGS} ${CFLAGS} \
		-o anal_nios.${LIBEXT} ${OBJ_NIOS}

