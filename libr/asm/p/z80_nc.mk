OBJ_Z80=asm_z80_nc.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=asm_z80_nc.${LIBEXT}

ALL_TARGETS+=${TARGET_Z80}

$(OBJ_Z80): %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,asm_z80_nc) ${CFLAGS} -o ${TARGET_Z80} ${OBJ_Z80} -lr_util
