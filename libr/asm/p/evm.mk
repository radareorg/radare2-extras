OBJ_EVM=asm_evm.o
OBJ_EVM+=../arch/evm/evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_EVM=asm_evm.${LIBEXT}

ALL_TARGETS+=${TARGET_EVM}

CFLAGS_EVM=$(CFLAGS)
CFLAGS_EVM+=-I../arch/evm
CFLAGS_EVM+=-Wall -shared -fPIC ${LDFLAGS_LIB}

$(OBJ_EVM): %.o : %.c
	$(CC) -c $(CFLAGS_EVM) $< -o $@

${TARGET_EVM}: ${OBJ_EVM}
	${CC} ${CFLAGS_EVM} ${LDFLAGS} -o ${TARGET_EVM} ${OBJ_EVM} -lr_util
