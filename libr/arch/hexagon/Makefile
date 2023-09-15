SO=$(shell r2 -H R2_LIBEXT)
PD=$(shell r2 -H R2_USER_PLUGINS)

CFLAGS+=$(shell pkg-config --cflags r_util r_arch) -fPIC
LDFLAGS+=$(shell pkg-config --libs r_util r_arch)
CFLAGS+=-g

OBJS=arch_hexagon.o
OBJS+=hexagon.o
OBJS+=hexagon_anal.o
OBJS+=hexagon_disas.o


all: arch_hexagon.${SO}

arch_hexagon.$(SO): $(OBJS)
	$(CC) -shared -fPIC -o arch_hexagon.$(SO) $(OBJS) $(LDFLAGS)
	rm -f $(PD)/arch_hexagon.$(SO)
	cp -f arch_hexagon.$(SO) $(PD)/arch_hexagon.$(SO)

clean:
	rm -f arch_hexagon.$(SO) $(OBJS)
