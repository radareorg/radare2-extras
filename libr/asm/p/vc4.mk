OBJ_VC4=arch_vc4.o
OBJ_VC4+=../arch/vc4/vc4-dis.o
OBJ_VC4+=../arch/vc4/vc4-asm.o
OBJ_VC4+=../arch/vc4/vc4-desc.o
OBJ_VC4+=../arch/vc4/vc4-ibld.o
OBJ_VC4+=../arch/vc4/vc4-opc.o
OBJ_VC4+=../arch/vc4/cgen-bitset.o
OBJ_VC4+=../arch/vc4/cgen-dis.o
OBJ_VC4+=../arch/vc4/cgen-asm.o
OBJ_VC4+=../arch/vc4/cgen-opc.o
OBJ_VC4+=../arch/vc4/libvc4/eval.o
OBJ_VC4+=../arch/vc4/libvc4/decode.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_decode.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_arch.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_util.o

SRC_VC4=$(patsubst %.o, %.c, $(OBJ_VC4))

CFLAGS_VC4=$(R2_CFLAGS)
CFLAGS_VC4+=-g -I$(TOP)/shlr
CFLAGS_VC4+=-Wall -shared -fPIC ${LDFLAGS_LIB}

CFLAGS_VC4+=-I../arch/vc4/libvc4/ -I../arch/vc4/include/ -I../arch/vc4/include/opcode/ -I../arch/include/

STATIC_OBJ+=${OBJ_VC4}
TARGET_VC4=arch_vc4.${LIBEXT}

ALL_TARGETS+=${TARGET_VC4}

$(OBJ_VC4): %.o : %.c
	$(CC) -c $(CFLAGS_VC4) $< -o $@

${TARGET_VC4}: ${OBJ_VC4}
	${CC} $(call libname,arch_vc4) ${LDFLAGS} ${CFLAGS_VC4} -o arch_vc4.${LIBEXT} ${OBJ_VC4}
