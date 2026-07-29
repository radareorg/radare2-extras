R2 ?= radare2
CARGO ?= cargo
SOEXT ?= $(shell $(R2) -H R2_LIBEXT)
PLUGDIR ?= $(shell $(R2) -H R2_USER_PLUGINS)
NAME=x86-iced
PLUGNAME=$(NAME).$(SOEXT)

all:
	$(CARGO) build --release
	mkdir -p $(PLUGDIR)
	cp -f target/release/libx86iced.$(SOEXT) $(PLUGDIR)/$(PLUGNAME)

uninstall:
	rm -f $(PLUGDIR)/$(PLUGNAME)
