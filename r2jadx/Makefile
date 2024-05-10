R2PM_PLUGDIR=$(shell r2pm -H R2PM_PLUGDIR)

all:
	$(MAKE) user-install

install user-install:
	mkdir -p ${R2PM_PLUGDIR}
	ln -fs $(shell pwd)/r2jadx.r2.js ${R2PM_PLUGDIR}/r2jadx.r2.js

uninstall user-uninstall::
	rm -f ${R2PM_PLUGDIR}/r2jadx.r2.js
