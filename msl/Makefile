# Memory Slice (.msl) plugins for radare2
#
#   io_msl     read a .msl as a process address space  (msl://)
#   bin_msl    parse a .msl: maps -> sections, regs -> a thread context
#   debug_msl  static debug backend over a .msl, incl. reverse exec (dsb/aesb)
#   core_msl   producer: "dgm"/"dgma" write a .msl from a live debug session

LIBEXT?=$(shell r2 -H R2_LIBEXT)
R2PM_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)

CFLAGS+=-fPIC -shared
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)

PLUGINS=io_msl.$(LIBEXT) bin_msl.$(LIBEXT) debug_msl.$(LIBEXT) core_msl.$(LIBEXT)

all: $(PLUGINS)

%.$(LIBEXT): %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

install: all
	mkdir -p "$(R2PM_PLUGDIR)"
	for a in $(PLUGINS) ; do rm -f "$(R2PM_PLUGDIR)/$$a" ; cp -f "$$a" "$(R2PM_PLUGDIR)" ; \
		codesign -f -s - "$(R2PM_PLUGDIR)/$$a" 2>/dev/null || true ; done

uninstall:
	for a in $(PLUGINS) ; do rm -f "$(R2PM_PLUGDIR)/$$a" ; done

user-install: install
user-uninstall: uninstall

clean:
	rm -f $(PLUGINS) *.o

.PHONY: all install uninstall user-install user-uninstall clean
