OBJ_EVM=asm_evm.o
OBJ_EVM+=../arch/evm/evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_EVM=asm_evm.${LIBEXT}

ALL_TARGETS+=${TARGET_EVM}
CFLAGS+=-I../arch/evm

${TARGET_EVM}: ${OBJ_EVM}
	${CC} ${CFLAGS} ${LDFLAGS} -o ${TARGET_EVM} ${OBJ_EVM} -lr_util

