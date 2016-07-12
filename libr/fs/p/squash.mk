OBJ_SQUASH=fs_squash.o

OBJ_SQUASH=fs_squash.o
OBJ_SQUASH+=../squashfs/compressor.o
OBJ_SQUASH+=../squashfs/gzip_wrapper.o
OBJ_SQUASH+=../squashfs/unsquash-1.o
OBJ_SQUASH+=../squashfs/unsquash-2.o
OBJ_SQUASH+=../squashfs/unsquash-3.o
OBJ_SQUASH+=../squashfs/unsquash-4.o
OBJ_SQUASH+=../squashfs/unsquashfs.o
OBJ_SQUASH+=../squashfs/xz_wrapper.o

CFLAGS+=-D GZIP_SUPPORT=1
CFLAGS+=-D XZ_SUPPORT=1
CFLAGS+=-I. -I/usr/local/include 
LDFLAGS+=-llzma
LDFLAGS+=-lz
CFLAGS+=-D HAVE_MAIN=0
CFLAGS+=-D XATTR_SUPPORT=1

STATIC_OBJ+=${OBJ_SQUASH}
TARGET_SQUASH=fs_squash.${LIBEXT}

ALL_TARGETS+=${TARGET_SQUASH}

${TARGET_SQUASH}: ${OBJ_SQUASH}
	${CC} $(call libname,fs_squash) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SQUASH} ${OBJ_SQUASH} ${EXTRA}
