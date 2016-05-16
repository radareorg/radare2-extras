OBJ_PSOSVM=asm_psosvm.o
OBJ_PSOSVM+=../arch/psosvm/vmas/vmas.o

STATIC_OBJ+=${OBJ_PSOSVM}
TARGET_PSOSVM=asm_psosvm.${LIBEXT}

ALL_TARGETS+=${TARGET_PSOSVM}

${TARGET_PSOSVM}: ${OBJ_PSOSVM}
	${CC} $(call libname,asm_psosvm) ${LDFLAGS} ${CFLAGS} -o asm_psosvm.${LIBEXT} ${OBJ_PSOSVM}
