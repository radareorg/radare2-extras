D=$(DESTDIR)/$(shell r2 -H R2_USER_PLUGINS)/iref-db
BINDIR=$(shell r2pm -H R2PM_BINDIR)
B=$(DESTDIR)/$(BINDIR)/

all:

clean:

install: user-install

user-uninstall uninstall:
	rm -f "$(B)/iref"
	rm -rf "$(D)"

user-install:
	mkdir -p "$(B)"
	cp iref.sh $(B)/iref
	chmod +x $(B)/iref
	mkdir -p "$(D)"
	tar xJvf iref-db.txz -C $(D)

sync: cutterref
	rm -rf iref-db
	cd cutterref/archs && tar cJvf ../../iref-db.txz *.sql

cutterref:
	git clone https://github.com/yossizap/cutterref

.PHONY: sync all install user-install user-uninstall uninstall clean
