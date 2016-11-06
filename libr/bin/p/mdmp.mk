OBJ_MDMP=bin_mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp.o
OBJ_MDMP+=../format/mdmp/mdmp_pe.o
OBJ_MDMP+=../format/mdmp/mdmp_pe64.o

STATIC_OBJ+=${OBJ_MDMP}
TARGET_MDMP=bin_mdmp.${EXT_SO}
libname=-shared -o $1.${LIBEXT}
CFLAGS+=-I../format/

libname=-shared -o $1.${LIBEXT}

ALL_TARGETS+=${TARGET_MDMP}

#ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_MDMP}
${TARGET_MDMP}: ${OBJ_MDMP}
	${CC} $(call libname,bin_mdmp) ${CFLAGS} \
	$(OBJ_MDMP) $(LINK) $(LDFLAGS)
#endif
