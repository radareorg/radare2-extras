NAME=anal_microblaze_gnu
R2_PLUGIN_PATH=$(shell r2 -hh|grep R2_LIBR_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC -Iinclude -Imicroblaze/gnu $(shell pkg-config --cflags r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_anal)
OBJS=$(NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

clean:
	    rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	    $(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	    cp -f $(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	    rm -f $(R2_PLUGIN_PATH)/$(NAME).$(SO_EXT)
