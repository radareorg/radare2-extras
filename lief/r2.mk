SO_EXT=dylib
R2_CFLAGS+=$(shell pkg-config --cflags r_bin r_util)
R2_LDFLAGS+=$(shell pkg-config --libs r_util r_bin)
