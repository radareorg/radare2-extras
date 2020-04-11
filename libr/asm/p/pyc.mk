OBJ_PYC=asm_pyc.o
OBJ_PYC+=../arch/pyc/opcode_10.o
OBJ_PYC+=../arch/pyc/opcode_11.o
OBJ_PYC+=../arch/pyc/opcode_12.o
OBJ_PYC+=../arch/pyc/opcode_13.o
OBJ_PYC+=../arch/pyc/opcode_14.o
OBJ_PYC+=../arch/pyc/opcode_15.o
OBJ_PYC+=../arch/pyc/opcode_16.o
OBJ_PYC+=../arch/pyc/opcode_20.o
OBJ_PYC+=../arch/pyc/opcode_21.o
OBJ_PYC+=../arch/pyc/opcode_22.o
OBJ_PYC+=../arch/pyc/opcode_23.o
OBJ_PYC+=../arch/pyc/opcode_24.o
OBJ_PYC+=../arch/pyc/opcode_25.o
OBJ_PYC+=../arch/pyc/opcode_26.o
OBJ_PYC+=../arch/pyc/opcode_27.o
OBJ_PYC+=../arch/pyc/opcode_2x.o
OBJ_PYC+=../arch/pyc/opcode_30.o
OBJ_PYC+=../arch/pyc/opcode_31.o
OBJ_PYC+=../arch/pyc/opcode_32.o
OBJ_PYC+=../arch/pyc/opcode_33.o
OBJ_PYC+=../arch/pyc/opcode_34.o
OBJ_PYC+=../arch/pyc/opcode_35.o
OBJ_PYC+=../arch/pyc/opcode_36.o
OBJ_PYC+=../arch/pyc/opcode_37.o
OBJ_PYC+=../arch/pyc/opcode_38.o
OBJ_PYC+=../arch/pyc/opcode_39.o
OBJ_PYC+=../arch/pyc/opcode_3x.o
OBJ_PYC+=../arch/pyc/opcode_arg_fmt.o
OBJ_PYC+=../arch/pyc/opcode_anal.o
OBJ_PYC+=../arch/pyc/opcode.o
OBJ_PYC+=../arch/pyc/pyc_dis.o

STATIC_OBJ+=${OBJ_PYC}
TARGET_PYC=asm_pyc.$(LIBEXT)

ALL_TARGETS+=${TARGET_PYC}
CFLAGS+=-I../arch/pyc

${TARGET_PYC}: ${OBJ_PYC}
	${CC} ${CFLAGS} $(LDFLAGS) -o ${TARGET_PYC} ${OBJ_PYC} -lr_util

