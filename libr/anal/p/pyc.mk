OBJ_PYC=asm_pyc.o
OBJ_PYC+=../arch/pyc/opcode_anal.o
OBJ_PYC+=../arch/pyc/opcode.o

STATIC_OBJ+=${OBJ_PYC}
TARGET_PYC=anal_pyc.$(LIBEXT)

ALL_TARGETS+=${TARGET_PYC}
CFLAGS+=-I../arch/pyc

${TARGET_PYC}: ${OBJ_PYC}
	${CC} ${CFLAGS} $(LDFLAGS) -o ${TARGET_PYC} ${OBJ_PYC} -lr_util
