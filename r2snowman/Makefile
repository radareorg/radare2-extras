PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
DESTDIR?=

all: snowman
	cd snowman ; git reset --hard
	cd snowman ; patch -p1 < ../snowman-r2.patch
	cd snowman/src ; cmake . ; make -j4
	cp -f snowman/src/snowman/snowman r2snow.bin
	$(MAKE) install

install:
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f r2snow.bin r2snow.pl r2snow $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/r2snow*

snowman:
	git clone https://github.com/yegord/snowman.git
