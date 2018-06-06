OBJ_NIOS=asm_nios.o

OBJ_NIOS+=../arch/nios/gnu/safe-ctype.o
OBJ_NIOS+=../arch/nios/gnu/cgen-bitset.o
OBJ_NIOS+=../arch/nios/gnu/cgen-dis.o
OBJ_NIOS+=../arch/nios/gnu/cgen-asm.o
OBJ_NIOS+=../arch/nios/gnu/cgen-opc.o
OBJ_NIOS+=../arch/nios/gnu/cpu-nios.o
OBJ_NIOS+=../arch/nios/gnu/nios-dis.o
OBJ_NIOS+=../arch/nios/gnu/nios-asm.o
OBJ_NIOS+=../arch/nios/gnu/nios-desc.o
OBJ_NIOS+=../arch/nios/gnu/nios-ibld.o
OBJ_NIOS+=../arch/nios/gnu/nios-opc.o

STATIC_OBJ+=${OBJ_NIOS}
TARGET_NIOS=asm_nios.${LIBEXT}

ALL_TARGETS+=${TARGET_NIOS}

${TARGET_NIOS}: ${OBJ_NIOS}
	${CC} $(call libname,asm_nios) ${LDFLAGS} ${CFLAGS} \
		-o asm_nios.${LIBEXT} ${OBJ_NIOS}
