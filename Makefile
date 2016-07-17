VERSION=0.10.4
HAVE_LIB_YARA=0
PREFIX=/usr
DESTDIR?=
TAR=tar -cvf
CZ=xz -f

DIRS=
ifeq ($(HAVE_LIB_YARA),1)
DIRS+=yara/yara2
DIRS+=yara/yara3
DIRS+=libr/asm/p
DIRS+=libr/anal/p
endif

help:
	@echo "Usage make [target]   .. Targets:"
	@echo "  all                - build everything"
	@echo "  baleful            - build baleful r2 plugin"
	@echo "  asm                - build armthumb, ppc, psosvm, x86bea, m68k plugins"
	@echo "  anal               - build analysis plugins (RAnal)"
	@echo "  debug              - build debugger plugins (RDebug)"
	@echo "  dlang              - support DLang demangler (RBin)"
	@echo "  yara{2,3}          - build yara2 or yara3 r2 plugin"
	@echo "  (target)-install   - install given plugin"
	@echo "  (target)-clean     - clean given plugin"
	@echo "  install-yara{2,3}  - install Yara 2 or 3 from Git"

baleful:
	$(MAKE) -C baleful
debug unicorn:
	$(MAKE) -C libr/debug/p
anal:
	$(MAKE) -C libr/anal/p
asm:
	$(MAKE) -C libr/asm/p
asm-install:
	$(MAKE) -C libr/asm/p install DESTDIR=$(DESTDIR)
asm-clean:
	$(MAKE) -C libr/asm/p clean
dlang:
	$(MAKE) -C libr/bin/p
dlang-install:
	$(MAKE) -C libr/bin/p install DESTDIR=$(DESTDIR)
yara2 yara3:
	cd yara/$@ ; ./configure --prefix=$(PREFIX)
	$(MAKE) -C yara/$@
yara2-clean:
	$(MAKE) -C yara/yara2 clean
yara3-clean:
	$(MAKE) -C yara/yara3 clean
baleful-install:
	$(MAKE) -C baleful install DESTDIR=$(DESTDIR)
debug-install unicorn-install:
	$(MAKE) -C libr/debug/p install DESTDIR=$(DESTDIR)
debug-uninstall unicorn-uninstall:
	$(MAKE) -C libr/debug/p uninstall DESTDIR=$(DESTDIR)
yara2-install:
	$(MAKE) -C yara/yara2 install DESTDIR=$(DESTDIR)
yara3-install:
	$(MAKE) -C yara/yara3 install DESTDIR=$(DESTDIR)

all:
	for a in $(DIRS) ; do \
	( cd $$a ; ./configure --prefix=$(PREFIX) ; $(MAKE) ) ; \
	done

clean mrproper install symstall uninstall deinstall:
	for a in $(DIRS) ; do ( cd $$a ; $(MAKE) $@ ) ; done

dist:
	DIR=`basename $$PWD` ; \
	FILES=`git ls-files | sed -e s,^,radare2-extras-${VERSION}/,` ; \
	cd .. && mv $${DIR} radare2-extras-${VERSION} && \
	${TAR} radare2-extras-${VERSION}.tar $${FILES} ; \
	${CZ} radare2-extras-${VERSION}.tar ; \
	mv radare2-extras-${VERSION} $${DIR}

w32dist:
	@echo TODO: w32dist

.PHONY: dist all
