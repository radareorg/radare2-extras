R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)

CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
CFLAGS+=-Igpu/wrap

all: gpu
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC arch_asahi.c -o arch_asahi.$(R2_LIBEXT)

mrproper clean:
	rm -f *.$(R2_LIBEXT)

gpu:
	git clone https://github.com/AsahiLinux/gpu

install:
	mkdir -p "$(R2_USER_PLUGINS)"
	cp -f arch_asahi.$(R2_LIBEXT) $(R2_USER_PLUGINS)

uninstall:
	rm -f $(R2_USER_PLUGINS)/arch_asahi.$(R2_LIBEXT)
