PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
DESTDIR?=

all: snowman
	cd snowman ; git reset --hard
	cd snowman/src ; cmake . ; make -j4
	cp -f snowman/src/nocode/nocode nocode

install:
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f nocode r2snow.pl r2snow $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/r2snow*

snowman:
	git clone https://github.com/yegord/snowman.git
