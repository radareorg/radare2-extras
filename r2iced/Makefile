SOEXT=$(shell r2 -H R2_LIBEXT)
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
NAME=x86-iced
PLUGNAME=$(NAME).$(SOEXT)

all:
	cargo build --release
	mkdir -p $(PLUGDIR)
	cp -f target/release/libr2iced.$(SOEXT) $(PLUGDIR)/$(PLUGNAME)

uninstall:
	rm -f $(PLUGDIR)/$(PLUGNAME)
