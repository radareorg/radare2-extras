BINDIR=$(shell r2pm -H R2PM_BINDIR)

all: cmsis-svd

cmsis-svd:
	git clone --depth=1 https://github.com/brainstorm/cmsis-svd && cd cmsis-svd && git checkout regex_fix
	pip3 install -t $(shell pwd)/cmsis-svd/python lxml six

clean:
	rm -rf cmsis-svd

install:
	$(MAKE) uninstall
	ln -fs "$(shell pwd)/r2svd.py" "$(BINDIR)/r2svd"
	chmod +x "$(BINDIR)/r2svd"

uninstall:
	rm -f $(BINDIR)/r2svd
