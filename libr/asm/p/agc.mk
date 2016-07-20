OBJ_AGC=asm_agc.o
OBJ_AGC+=../arch/agc/asm_agc.o

STATIC_OBJ+=${OBJ_AGC}
TARGET_AGC=asm_agc.${LIBEXT}

ALL_TARGETS+=${TARGET_AGC}

${TARGET_AGC}: ${OBJ_AGC}
	${CC} $(call libname,asm_armthumb) ${LDFLAGS} \
		${CFLAGS} -o ${TARGET_AGC} ${OBJ_AGC}
