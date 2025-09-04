OBJ_ARMTHUMB=arch_armthumb.o
OBJ_ARMTHUMB+=armthumb_src.o

STATIC_OBJ+=${OBJ_ARMTHUMB}
TARGET_ARMTHUMB=arch_armthumb.${LIBEXT}

ALL_TARGETS+=${TARGET_ARMTHUMB}

arch_armthumb.o: arch_armthumb.c
	$(CC) -c $(CFLAGS) $< -o $@

armthumb_src.o: ../arch/arm/armthumb.c
	$(CC) -c $(CFLAGS) -I../arch/arm -o $@ $<

${TARGET_ARMTHUMB}: ${OBJ_ARMTHUMB}
	${CC} $(call libname,arch_armthumb) ${LDFLAGS} \
		${CFLAGS} -o ${TARGET_ARMTHUMB} ${OBJ_ARMTHUMB}
