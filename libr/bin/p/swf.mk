OBJ_SWF=bin_swf.o
OBJ_SWF+=../format/swf/swf.o

STATIC_OBJ+=${OBJ_SWF}
TARGET_SWF=bin_swf.$(EXT_SO)

ALL_TARGETS+=${TARGET_SWF}
CFLAGS+=-I../format/swf

${TARGET_SWF}: ${OBJ_SWF}
	${CC} ${CFLAGS} -o ${TARGET_SWF} ${OBJ_SWF}

