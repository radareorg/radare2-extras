LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

CORE_AFEN=src/libcoreafen.$(LIBEXT)
OBJS=src/main.o

all: $(CORE_AFEN)

$(CORE_AFEN): $(OBJS)
	r2pm -r $(CC) $(LDFLAGS) -shared -fPIC -o $(CORE_AFEN) $(OBJS)

clean:
	rm -f $(OBJS) $(CORE_AFEN)

user-install install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(CORE_AFEN) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/$(CORE_AFEN)
