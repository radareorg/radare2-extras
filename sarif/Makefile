all:
	r2 -i sarif.r2.js /bin/ls

install user-install:
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	cp -f sarif.r2.js $(shell r2 -H R2_USER_PLUGINS)

uninstall user-uninstall:
	rm -f $(shell r2 -H R2_USER_PLUGINS)/sarif.r2.js

indent:
	semistandard --fix sarif.r2.js
