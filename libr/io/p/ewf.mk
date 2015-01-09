OBJ_EWF=io_ewf.o

STATIC_OBJ+=${OBJ_EWF}
TARGET_EWF=io_ewf.${EXT_SO}
ALL_TARGETS+=${TARGET_EWF}

ifeq (${HAVE_LIB_EWF},1)
CFLAGS+=${EWF_CFLAGS}
LDFLAGS+=${EWF_LDFLAGS}
CFLAGS+=${R2_CFLAGS}
LDFLAGS+=${R2_LDFLAGS}
endif
#/opt/local/include

ifeq (${HAVE_LIB_EWF},1)
${TARGET_EWF}: ${OBJ_EWF}
	#${CC_LIB} $(call libname,io_ewf) ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
	${CC} -shared ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
endif
