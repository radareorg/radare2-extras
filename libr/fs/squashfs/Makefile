#CFLAGS+=-D LZMA_SUPPORT=1
CFLAGS+=-D GZIP_SUPPORT=1
CFLAGS+=-D XZ_SUPPORT=1
CFLAGS+=-D XATTR_SUPPORT=1
CFLAGS+=-I. -I/usr/local/include 
LDFLAGS+=-llzma
LDFLAGS+=-lz

BIN=unsquashfs

all:
	gcc ${CFLAGS} *.c $(LDFLAGS) -o $(BIN)

clean:
	rm -f $(BIN)
