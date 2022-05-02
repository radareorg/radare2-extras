OBJ_X86_BEA=asm_x86_bea.o
OBJ_X86_BEA+=../arch/x86/bea/BeaEngine.o

STATIC_OBJ+=${OBJ_X86_BEA}
TARGET_X86_BEA=asm_x86_bea.$(LIBEXT)

ALL_TARGETS+=${TARGET_X86_BEA}
CFLAGS_BEA=-I../arch/x86/bea/
CFLAGS_BEA+=-I../arch/x86/bea/src
CFLAGS_BEA+=-I../arch/x86/bea/include
CFLAGS_BEA+=-DUint64=uint64_t

$(OBJ_X86_BEA): %.o : %.c
	$(CC) -c $(CFLAGS) $(CFLAGS_BEA) $< -o $@

${TARGET_X86_BEA}: ${OBJ_X86_BEA}
	${CC} ${CFLAGS} ${CFLAGS_BEA} -o ${TARGET_X86_BEA} ${OBJ_X86_BEA} ${LDFLAGS}
