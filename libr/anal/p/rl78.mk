OBJ_RL78=anal_rl78.o

STATIC_OBJ+=${OBJ_RL78}
TARGET_RL78=anal_rl78.${LIBEXT}

ALL_TARGETS+=${TARGET_RL78}

CFLAGS+=-I../../asm/arch
CFLAGS+=-I../../asm/arch/include

${TARGET_RL78}: ${OBJ_RL78}
	${CC} $(call libname,anal_rl78) ${LDFLAGS} ${CFLAGS} \
		-o anal_rl78.${LIBEXT} ${OBJ_RL78}

