OBJ_EVM=anal_evm.o
OBJ_EVM+=../../asm/arch/evm/evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_evm=anal_evm.${LIBEXT}

ALL_TARGETS+=${TARGET_evm}
LINKFLAGS+=-ljansson

CFLAGS_EVM=$(CFLAGS)
CFLAGS_EVM+=-I../../asm/arch/evm
CFLAGS_EVM+=-Wall -shared -fPIC ${LDFLAGS_LIB}

$(OBJ_EVM): %.o : %.c
	$(CC) -c $(CFLAGS_EVM) $< -o $@

${TARGET_evm}: ${OBJ_EVM} ${SHARED_OBJ}
	${CC} $(call libname,anal_evm) ${LDFLAGS} ${CFLAGS_EVM} -o ${TARGET_evm} ${OBJ_EVM} ${LINKFLAGS}
