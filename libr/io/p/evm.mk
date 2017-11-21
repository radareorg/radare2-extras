OBJ_EVM=io_evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_EVM=io_evm.${LIBEXT}
ALL_TARGETS+=${TARGET_EVM}

ifeq (${WITHPIC},0)
LINKFLAGS+=-lcurl -ljansson
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-lcurl -ljansson
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_EVM}: ${OBJ_EVM}
	${CC} $(call libname,io_evm) ${CFLAGS} -o ${TARGET_EVM} \
		${LDFLAGS} ${OBJ_EVM} ${LINKFLAGS}
