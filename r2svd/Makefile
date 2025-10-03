BINDIR=$(shell r2pm -H R2PM_BINDIR)
PIP=$(or $(shell command -v uv >/dev/null && echo uv pip), pip3)

all: cmsis-svd

cmsis-svd:
	git clone --depth=1 https://github.com/cmsis-svd/cmsis-svd && cd cmsis-svd
	$(PIP) install --target $(shell pwd)/cmsis-svd/python lxml six

clean:
	rm -rf cmsis-svd

install:
	$(MAKE) uninstall
	ln -fs "$(shell pwd)/r2svd.py" "$(BINDIR)/r2svd"
	chmod +x "$(BINDIR)/r2svd"

uninstall:
	rm -f $(BINDIR)/r2svd
