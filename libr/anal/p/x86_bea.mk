OBJ_X86_BEA=anal_x86_bea.o
OBJ_X86_BEA+=../../asm/arch/x86/bea/BeaEngine.o

STATIC_OBJ+=${OBJ_X86_BEA}
TARGET_X86_BEA=anal_x86_bea.${LIBEXT}

ALL_TARGETS+=${TARGET_X86_BEA}
CFLAGS+=-I../../asm/arch/x86/bea/
CFLAGS+=-I../../asm/arch/x86/bea/src
CFLAGS+=-I../../asm/arch/x86/bea/include
CFLAGS+=-DUint64=uint64_t

${TARGET_X86_BEA}: ${OBJ_X86_BEA}
	${CC} ${CFLAGS} -o anal_x86_bea.${LIBEXT} ${OBJ_X86_BEA}
	@#strip -s anal_x86_bea.${LIBEXT}
