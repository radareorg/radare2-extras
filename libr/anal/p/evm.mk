OBJ_EVM=anal_evm.o
OBJ_EVM+=../../asm/arch/evm/evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_evm=anal_evm.${LIBEXT}

ALL_TARGETS+=${TARGET_evm}
LINKFLAGS+=-ljansson

$(OBJ_EVM): %.o : %.c
	$(CC) -c $(CFLAGS) -I../../asm/arch/evm/ $< -o $@

${TARGET_evm}: ${OBJ_EVM} ${SHARED_OBJ}
	${CC} $(call libname,anal_evm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_evm} ${OBJ_EVM} ${LINKFLAGS}
