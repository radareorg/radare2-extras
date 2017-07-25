SO_EXT=dylib
LIEF_SRC=$(shell pwd)/../LIEF
LIEF_CFLAGS+=-I$(LIEF_SRC)/api/c/include -fPIC
LIEF_CFLAGS+=-I$(LIEF_SRC)/include -fPIC
LIEF_LDFLAGS+=$(LIEF_SRC)/libLIEF.a -shared
