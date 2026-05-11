R2PM_PLUGDIR=$(shell r2pm -H R2PM_PLUGDIR)
R2FRIDA_COMPILE=r2pm -r r2frida-compile
ENTRY=src/r2jadx.ts
SRC=$(wildcard src/*.ts)
OUT=r2jadx.r2.js

all: $(OUT)

$(OUT): $(SRC)
	$(R2FRIDA_COMPILE) -S -B iife -o $@ $(ENTRY)

install user-install: $(OUT)
	mkdir -p ${R2PM_PLUGDIR}
	ln -fs $(shell pwd)/r2jadx.r2.js ${R2PM_PLUGDIR}/r2jadx.r2.js

uninstall user-uninstall::
	rm -f ${R2PM_PLUGDIR}/r2jadx.r2.js

clean:
	rm -f $(OUT)

.PHONY: all clean r2jadx.r2.js
