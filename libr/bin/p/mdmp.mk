OBJ_MDMP=bin_mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp_pe.o
OBJ_MDMP+=../format/mdmp/mdmp_pe64.o

STATIC_OBJ+=${OBJ_MDMP}
TARGET_MDMP=bin_mdmp.${LIBEXT}
CFLAGS+=-I../format/


ALL_TARGETS+=${TARGET_MDMP}

ALL_TARGETS+=${TARGET_MDMP}
${TARGET_MDMP}: ${OBJ_MDMP}
	${CC} ${CFLAGS} -o ${TARGET_MDMP} $(OBJ_MDMP) $(R2_CFLAGS) $(R2_LDFLAGS)
