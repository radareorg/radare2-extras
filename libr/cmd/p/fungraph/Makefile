VALAFLAGS+=--pkg r_core --pkg r_anal --pkg r_util --pkg r_lib --pkg r_cmd --pkg r_config
VALAFLAGS+=--pkg gtk+-2.0

VALAFILES=plugin.vala

BIN=rfg

all:
	rm -f rfg.so
	${MAKE} rfg.so
	mkdir -p ~/.radare2/plugins
	cp rfg.so ~/.radare2/plugins

rfg.so:
	valac -g -o rfg.so --library=rfg --Xcc=-fPIC --Xcc=-shared \
		${VALAFLAGS} ${VALAFILES}

clean:
	rm -f *.c

mrproper: clean
	rm -f rfg rfg.so
