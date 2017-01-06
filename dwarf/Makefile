libdwarf=/home/panda/rsoc/p4n74/code/
sdb=/home/panda/rsoc/p4n74/sdb/

all:
	gcc -g -O2 -I. -I$(libdwarf)libdwarf -I$(sdb)src -DCONFPREFIX=/usr/local/lib main.c -o dparser -L$(libdwarf)libdwarf $(sdb)src/libsdb.a -ldwarf -lelf -lz

clean:
	rm dparser
