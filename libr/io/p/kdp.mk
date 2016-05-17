OBJ_KDP=io_kdp.o

STATIC_OBJ+=${OBJ_KDP}
TARGET_KDP=io_kdp.${LIBEXT}
ALL_TARGETS+=${TARGET_KDP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_KDP}: ${OBJ_KDP}
	${CC_LIB} $(call libname,io_kdp) ${CFLAGS} -o ${TARGET_KDP} \
		${LDFLAGS} ${OBJ_KDP} ${LINKFLAGS}
