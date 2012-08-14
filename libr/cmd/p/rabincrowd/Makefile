VALAFLAGS=--vapidir=../swig/vapi
VALAFLAGS+=--vapidir=. --pkg xmlrpc
VALAFLAGS+=--Xcc="-Wl,-lxmlrpc" --Xcc="-Wl,-lxmlrpc_client"
VALAFLAGS+=--pkg r_core --pkg r_anal --pkg r_util --pkg r_asm --pkg r_lib --pkg r_cmd --pkg r_config

VALAFILES=node.vala edge.vala function.vala target.vala
VALAFILES+=radaretarget.vala bincrowd.vala primes.vala argument.vala

BIN=rbc

all:
	rm -f rbc.so
	${MAKE} rbc.so
	mkdir -p ~/.radare2/plugins
	cp rbc.so ~/.radare2/plugins

rbc:
	valac -g -o ${BIN} ${VALAFLAGS} ${VALAFILES} main.vala

rbc.so:
	valac -g -o rbc.so --library=rbc --Xcc=-fPIC --Xcc=-shared \
		${VALAFLAGS} ${VALAFILES} plugin.vala

c:
	valac -C ${VALAFLAGS} ${VALAFILES} plugin.vala main.vala

sync:
	cd .. && rsync -avz rabincrowd pancake@radare.org:/srv/http/radareorg/

clean:
	rm -f *.c

mrproper: clean
	rm -f rbc rbc.so
