OBJ_Z80=../arch/z80_nc/z80.o \
	../arch/z80_nc/disasm.o \
	../arch/z80_nc/test.o \
	asm_z80_nc.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=asm_z80_nc.${LIBEXT}

ALL_TARGETS+=${TARGET_Z80}

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,asm_z80_nc) ${CFLAGS} -o ${TARGET_Z80} ${OBJ_Z80}
