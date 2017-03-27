all:
	$(CC) $(shell pkg-config --cflags --libs r_bin) bin_md380fw.c -shared -fPIC -o bin_md380fw.dylib
	mkdir -p $(shell r2 -H USER_PLUGINS)/plugins
	cp -f *.dylib $(shell r2 -H USER_PLUGINS)/plugins
