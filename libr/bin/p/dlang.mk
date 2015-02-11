OBJ_DLANG=bin_dlang.o
OBJ_DLANG+=dmangle.o

STATIC_OBJ+=${OBJ_DLANG}
TARGET_DLANG=bin_dlang.${EXT_SO}

ALL_TARGETS+=${TARGET_DLANG}
#LDFLAGS+= -lphobos2 -lpthread
LDFLAGS+=-lphobos2-ldc

#DMD=dmd -fPIC
DMD=ldc2 -relocation-model=pic

dmangle.o:
	$(DMD) -c ../arch/dlang/dmangle.d

${TARGET_DLANG}: ${OBJ_DLANG}
	${CC} $(call libname,bin_dlang) ${LDFLAGS} \
		${CFLAGS} -o bin_dlang.${EXT_SO} ${OBJ_DLANG}
