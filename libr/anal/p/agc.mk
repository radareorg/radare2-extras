OBJ_AGC=anal_agc.o

STATIC_OBJ+=${OBJ_AGC}
TARGET_AGC=anal_agc.${LIBEXT}

ALL_TARGETS+=${TARGET_AGC}

${TARGET_AGC}: ${OBJ_AGC}
	${CC} $(call libname,anal_agc) ${LDFLAGS} \
		${CFLAGS} -o anal_agc.${LIBEXT} ${OBJ_AGC}
