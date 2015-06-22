MODS=r_debug r_reg r_util
CFLAGS+=$(shell pkg-config --cflags ${MODS})
LDFLAGS+=$(shell pkg-config --libs ${MODS})
W32OBJ=debug_windows.o
#included drx.o reg.o

CFLAGS+=-fPIC

include ../../../options.mk

all: debug_windows.$(EXT_SO)

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c $< -o $@

debug_windows.$(EXT_SO): $(W32OBJ)
	$(CC) -shared -fPIC $(CFLAGS) -o debug_windows.$(EXT_SO) $(W32OBJ) $(LDFLAGS)

clean:
	rm *.$(EXT_SO) *.o
