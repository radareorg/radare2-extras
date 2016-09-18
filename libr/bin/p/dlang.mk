OBJ_DLANG=bin_dlang.o
OBJ_DLANG+=dmangle.o

STATIC_OBJ+=${OBJ_DLANG}
TARGET_DLANG=bin_dlang.${LIBEXT}
CFLAGS+=-I../format

ALL_TARGETS+=${TARGET_DLANG}
#LDFLAGS+= -lphobos2 -lpthread
DLANG_LDFLAGS+=-lphobos2-ldc

#DMD=dmd -fPIC
DMD=ldc2 -relocation-model=pic

dmangle.o:
	$(DMD) -c ../format/dlang/dmangle.d

${TARGET_DLANG}: ${OBJ_DLANG}
	${CC} $(call libname,bin_dlang) ${LDFLAGS} $(DLANG_LDFLAGS) \
		${CFLAGS} -o bin_dlang.${LIBEXT} ${OBJ_DLANG}
