-include config.mk

ifeq ($(BUILD_OS),darwin)
SO_EXT=dylib
LDFLAGS_SHARED=-dynamiclib
else
LDFLAGS_SHARED=-shared
ifeq ($(BUILD_OS),windows)
SO_EXT=dll
else
SO_EXT=so
endif
endif

KS_CFLAGS=$(shell pkg-config --cflags keystone)
KS_LDFLAGS=$(shell pkg-config --libs keystone)
KS_LINK=-lkeystone
CFLAGS+=-Wextern-c-compat
