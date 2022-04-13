CFLAGS+=$(shell pkg-config --cflags r_util)
CFLAGS+=$(shell pkg-config --cflags SDL)
#CFLAGS+=-fsanitize=address
CFLAGS+=-g
LDFLAGS+=$(shell pkg-config --libs r_util r_io r_cons r_core)
LDFLAGS+=$(shell pkg-config --libs SDL)
ifeq ($(shell uname),Linux)
LDFLAGS+=-lm
endif
LIBEXT=$(shell r2 -H LIBEXT)
R2P=$(shell r2 -H R2_USER_PLUGINS)

all:
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC core_gamepad.c -o core_gamepad.$(LIBEXT)
	mkdir -p $(R2P)
	cp -rf core_gamepad.$(LIBEXT)* $(R2P)
	r2 -c 'god mode on' /bin/ls
