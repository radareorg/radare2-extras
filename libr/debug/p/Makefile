MODS=r_debug r_reg r_util
USER_PLUGINS=$(shell r2 -H USER_PLUGINS)
LDFLAGS+=$(shell pkg-config --libs ${MODS}) -g
CFLAGS+=$(shell pkg-config --cflags ${MODS}) -g -I/usr/local/include -L/usr/local/lib
W32OBJ=debug_windows.o
include unicorn.mk

CFLAGS+=-fPIC

include ../../../options.mk

all: debug_windows.$(LIBEXT) debug_unicorn.$(LIBEXT)

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c $< -o $@

debug_windows.$(LIBEXT): $(W32OBJ)
	$(CC) -shared -fPIC $(CFLAGS) -o debug_windows.$(LIBEXT) $(W32OBJ) $(LDFLAGS)

install: uninstall
	mkdir -p ~/.config/radare2/plugins/
	cp -f debug_unicorn.$(LIBEXT) $(USER_PLUGINS)
	ls -l $(USER_PLUGINS)/debug_unicorn.$(LIBEXT)

uninstall:
	rm -f $(USER_PLUGINS)/debug_unicorn.${LIBEXT} 

clean:
	rm *.$(LIBEXT) *.o
