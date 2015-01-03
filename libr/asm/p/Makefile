include ../../../options.mk
CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared -fPIC ${LDFLAGS_LIB}
# ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
LDFLAGS+=-L../../util -L../../lib
LDFLAGS+=${LINK} -lr_util

CURDIR=

foo: all

ALL_TARGETS=
ARCHS=

ARCHS+=armthumb.mk 
ARCHS+=ppc_disasm.mk
# doesnt build yet
#ARCHS+=m68k.mk
#ARCHS+=x86_bea.mk

include $(ARCHS)

all: ${ALL_TARGETS}

THEDIR=$(LIBDIR)/radare2-extras/$(VERSION)

install:
	mkdir -p $(THEDIR)
	cp -f *.$(EXT_SO) $(THEDIR)

symstall:
	mkdir -p $(THEDIR)
	cp -f *.$(EXT_SO) $(THEDIR)

uninstall:
	for a in *.$(EXT_SO) ; do rm -f $(THEDIR)/$$a ; done

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all install symstall uninstall clean foo mrproper
