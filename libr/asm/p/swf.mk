OBJ_SWF=asm_swf.o
OBJ_SWF+=../arch/swf/swfdis.o

STATIC_OBJ+=${OBJ_SWF}
TARGET_SWF=asm_swf.$(LIBEXT)

ALL_TARGETS+=${TARGET_SWF}
CFLAGS+=-I../arch/swf

${TARGET_SWF}: ${OBJ_SWF}
	${CC} ${CFLAGS} $(LDFLAGS) -o ${TARGET_SWF} ${OBJ_SWF} -lr_util

