NAME=zpu
R2_PLUGIN_PATH=$(shell r2 -hh|grep R2_LIBR_PLUGINS|awk '{print $$2}')
CFLAGS_ZPU=-g -fPIC $(shell pkg-config --cflags r_asm)
LDFLAGS=-shared $(shell pkg-config --libs r_asm)
OBJS=$(NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

clean:
	rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	$(CC) $(CFLAGS_ZPU) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	cp -f $(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(NAME).$(SO_EXT)
