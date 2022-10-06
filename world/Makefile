SOEXT=$(shell r2 -H R2_LIBEXT)
R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)

all:
	$(CC) $(shell pkg-config --cflags --libs r_core) -shared -fPIC -o pwm.$(SOEXT) pwm.c

user-uninstall:
	rm -f $(R2_USER_PLUGINS)/pwm.$(SOEXT)

user-install:
	cp -f pwm.$(SOEXT) $(R2_USER_PLUGINS)

geoip:
	wget -c https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv
