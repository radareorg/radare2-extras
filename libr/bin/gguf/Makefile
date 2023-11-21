LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_bin)
LDFLAGS+=$(shell pkg-config --libs r_bin)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

BIN_GGUF=src/bin_gguf.$(LIBEXT)
OBJS=src/bin_gguf.o

all: $(BIN_GGUF)

$(BIN_GGUF): $(OBJS)
	$(CC) $(LDFLAGS) -shared -fPIC -o $(BIN_GGUF) $(OBJS)

clean:
	rm -f $(OBJS) $(BIN_GGUF)

user-install install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(BIN_GGUF) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/$(BIN_GGUF)
