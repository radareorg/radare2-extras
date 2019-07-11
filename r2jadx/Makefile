R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)

all: node_modules

node_modules:
	mkdir -p node_modules
	npm i

install:
	ln -fs "$(shell pwd)"/r2jadx.js "$(R2PM_BINDIR)"/r2jadx

uninstall:
	rm -f "$(R2PM_BINDIR)"/r2jadx

test:
	r2 -A -i ./r2jadx.js /tmp/classes.dex

indent:
	node_modules/.bin/semistandard --fix *.js
