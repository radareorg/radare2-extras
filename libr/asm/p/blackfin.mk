#OBJ_BLACKFIN+=../arch/blackfin/bfin-dis.o 
OBJ_BLACKFIN+= asm_blackfin.o

STATIC_OBJ+=${OBJ_BLACKFIN}
TARGET_BLACKFIN=asm_blackfin.${EXT_SO}

ALL_TARGETS+=${TARGET_BLACKFIN}

${TARGET_BLACKFIN}: ${OBJ_BLACKFIN}
	${CC} ${CFLAGS} -o asm_blackfin.${EXT_SO} ${OBJ_BLACKFIN}
