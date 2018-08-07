all:
	$(CC) $(shell pkg-config --cflags --libs r_bin) bin_md380fw.c -shared -fPIC -o bin_md380fw.dylib
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	cp -f *.dylib $(shell r2 -H R2_USER_PLUGINS)
