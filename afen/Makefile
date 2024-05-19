LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

CORE_HELLO=src/core_hello.$(LIBEXT)
OBJS=src/core_hello.o

all: $(CORE_HELLO)

$(CORE_HELLO): $(OBJS)
	r2pm -r $(CC) $(LDFLAGS) -shared -fPIC -o $(CORE_HELLO) $(OBJS)

clean:
	rm -f $(OBJS) $(CORE_HELLO)

user-install install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(CORE_HELLO) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/$(CORE_HELLO)
