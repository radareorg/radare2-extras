OBJ_DCPU16=arch_dcpu16.o
#OBJ_DCPU16+=../arch/dcpu16/asm.o
#OBJ_DCPU16+=../arch/dcpu16/dis.o

STATIC_OBJ+=${OBJ_DCPU16}
TARGET_DCPU16=arch_dcpu16.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_DCPU16}

${TARGET_DCPU16}: ${OBJ_DCPU16}
	${CC} $(call libname,arch_dcpu16) ${LDFLAGS} ${CFLAGS} -o ${TARGET_DCPU16} ${OBJ_DCPU16}
endif
