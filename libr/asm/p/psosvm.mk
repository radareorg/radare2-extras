OBJ_PSOSVM=arch_psosvm.o
OBJ_PSOSVM+=../arch/psosvm/vmas/vmas.o

STATIC_OBJ+=${OBJ_PSOSVM}
TARGET_PSOSVM=arch_psosvm.${LIBEXT}

ALL_TARGETS+=${TARGET_PSOSVM}

${TARGET_PSOSVM}: ${OBJ_PSOSVM}
	${CC} $(call libname,arch_psosvm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_PSOSVM} ${OBJ_PSOSVM}
