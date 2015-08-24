OBJ_UNICORN=debug_unicorn.o
CFLAGS+=-I/usr/include/unicorn
UNICORN_LDFLAGS=-lunicorn

libname=-shared -o $1.${EXT_SO}

STATIC_OBJ+=${OBJ_UNICORN}
TARGET_UNICORN=debug_unicorn.${EXT_SO}

ALL_TARGETS+=${TARGET_UNICORN}

CFLAGS+=${R2_CFLAGS}

${TARGET_UNICORN}: ${OBJ_UNICORN}
	${CC} $(call libname,debug_unicorn) ${CFLAGS} \
		${UNICORN_LDFLAGS} ${R2_CFLAGS} \
		${R2_LDFLAGS} ${OBJ_UNICORN}
