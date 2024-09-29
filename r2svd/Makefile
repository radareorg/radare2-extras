BINDIR=$(shell r2pm -H R2PM_BINDIR)

all: cmsis-svd

cmsis-svd:
	git clone https://github.com/brainstorm/cmsis-svd && cd cmsis-svd && git checkout regex_fix

install:
	cp -f r2svd.py $(BINDIR)/r2svd
	chmod +x $(BINDIR)/r2svd

uninstall:
	rm -f $(BINDIR)/r2svd.py
