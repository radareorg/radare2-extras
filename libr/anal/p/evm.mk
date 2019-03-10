OBJ_evm=anal_evm.o
OBJ_evm+=../../asm/arch/evm/evm.o
CFLAGS+=-I../../asm/arch/evm/

STATIC_OBJ+=${OBJ_evm}
TARGET_evm=anal_evm.${LIBEXT}

ALL_TARGETS+=${TARGET_evm}
LINKFLAGS+=-ljansson

${TARGET_evm}: ${OBJ_evm} ${SHARED_OBJ}
	${CC} $(call libname,anal_evm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_evm} ${OBJ_evm} ${LINKFLAGS}
