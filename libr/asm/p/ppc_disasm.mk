OBJ_PPC_DISASM=arch_ppc_disasm.o
OBJ_PPC_DISASM+=../arch/ppc/ppc_disasm/ppc_disasm.o

STATIC_OBJ+=${OBJ_PPC_DISASM}
TARGET_PPC_DISASM=arch_ppc_disasm.${LIBEXT}

ALL_TARGETS+=${TARGET_PPC_DISASM}

${TARGET_PPC_DISASM}: ${OBJ_PPC_DISASM}
	${CC} ${CFLAGS} -o ${TARGET_PPC_DISASM} ${OBJ_PPC_DISASM} ${LDFLAGS}

# Keep older r2pm recipes working until they use the arch_ target.
asm_ppc_disasm.${LIBEXT}: ${TARGET_PPC_DISASM}
	cp -f ${TARGET_PPC_DISASM} $@
