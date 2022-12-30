R2_PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
LDFLAGS=-L/opt/homebrew/lib

# VFLAGS+=-gc none

ifeq ($(R2_LIBEXT),)
all:
	@echo Cannot find r2
else

all:
	v install --once
	v fmt -w pdv.v main.v east
	v -o a.c -shared pdv.v
	LDFLAGS=$(LDFLAGS) v -o pdv.$(R2_LIBEXT) -shared pdv.v
	install -m 0755 pdv.$(R2_LIBEXT) $(R2_PLUGDIR)
	v $(VFLAGS) -g main.v
	./main

setup:
	v install
endif
