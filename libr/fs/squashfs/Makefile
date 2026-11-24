#CFLAGS+=-D LZMA_SUPPORT=1
CFLAGS+=-D GZIP_SUPPORT=1
CFLAGS+=-D XZ_SUPPORT=1
CFLAGS+=-D XATTR_SUPPORT=1
CFLAGS+=-I. -I/usr/local/include 
CFLAGS+=-Ilzma/include
CFLAGS+=-g
LDFLAGS+=-llzma
LDFLAGS+=-lz
LDFLAGS+=-lpthread

SOURCES+=compressor.c
SOURCES+=gzip_wrapper.c
SOURCES+=unsquash-1.c
SOURCES+=unsquash-2.c
SOURCES+=unsquash-3.c
SOURCES+=unsquash-4.c
SOURCES+=unsquashfs.c
SOURCES+=xz_wrapper.c

BIN=unsquashfs
R2 ?= r2
R2PLUGDIR ?= $(shell $(R2) -H R2_USER_PLUGINS)
RHOMEBIN ?= $(R2PLUGDIR)/../prefix/bin

.PHONY: all clean
all: $(BIN)
	$(MAKE) -C ../p install-squash
	mkdir -p "$(DESTDIR)$(RHOMEBIN)"
	cp $(BIN) "$(DESTDIR)$(RHOMEBIN)/unsquashfs"

$(BIN): $(SOURCES)
	$(CC) ${CFLAGS} $(SOURCES) $(LDFLAGS) -o $(BIN)

clean:
	rm -f $(BIN)
