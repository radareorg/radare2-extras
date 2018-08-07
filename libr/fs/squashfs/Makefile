LIB=fs_squashfs.$(EXT_SO)
R2PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
RHOMEBIN=$(shell r2 -H RHOMEDIR)/prefix/bin

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

R2_FLAGS+=$(shell pkg-config --cflags --libs r_fs)

SOURCES+=compressor.c
SOURCES+=gzip_wrapper.c
SOURCES+=unsquash-1.c
SOURCES+=unsquash-2.c
SOURCES+=unsquash-3.c
SOURCES+=unsquash-4.c
SOURCES+=unsquashfs.c
SOURCES+=xz_wrapper.c

BIN=unsquashfs

EXT_SO?=$(shell r2 -H LIBEXT)

#all: fs_squashfs.$(EXT_SO) $(BIN)
all: $(LIB) $(BIN)
	cp -f $(LIB) $(R2PLUGDIR)
	cp -rf $(LIB)* $(R2PLUGDIR)
	cp -f unsquashfs $(RHOMEBIN)

$(BIN):
	$(CC) ${CFLAGS} $(SOURCES) $(LDFLAGS) -o $(BIN)

$(LIB):
	$(CC) -DAPIMODE=1 -fPIC -shared $(R2_FLAGS) $(CFLAGS) $(LDFLAGS) -o $(LIB) fs_squashfs.c $(SOURCES)

.PHONY: $(LIB) $(BIN)

clean:
	rm -f $(BIN)
