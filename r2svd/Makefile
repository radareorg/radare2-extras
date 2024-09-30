BINDIR=$(shell r2pm -H R2PM_BINDIR)

all: cmsis-svd

cmsis-svd:
	git clone --depth=1 https://github.com/brainstorm/cmsis-svd && cd cmsis-svd && git checkout regex_fix
	cd cmsis-svd/python && python3 setup.py build
	cd cmsis-svd/python && python3 setup.py install

clean:
	rm -rf cmsis-svd

install:
	cp -f r2svd.py $(BINDIR)/r2svd
	chmod +x $(BINDIR)/r2svd

uninstall:
	rm -f $(BINDIR)/r2svd.py
