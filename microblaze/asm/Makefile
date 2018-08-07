NAME=asm_microblaze_gnu
R2_PLUGIN_PATH=$(shell r2 -hh|grep R2_LIBR_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC -Iinclude $(shell pkg-config --cflags r_asm)
LDFLAGS=-shared $(shell pkg-config --libs r_asm)
OBJS=$(NAME).o
OBJS+=microblaze/gnu/microblaze-dis.o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

.c:
		$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

.c.o:
		$(CC) -c $(CFLAGS) -o $@ $<

clean:
	    rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	    $(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	    cp -f asm_microblaze_gnu.$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	    rm -f $(R2_PLUGIN_PATH)/$name.$(SO_EXT)

