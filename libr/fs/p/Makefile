ARCHS=
CFLAGS+=-g
LDFLAGS+=-g

ARCHS+=squash.mk 
#ARCHS+=jffs2.mk 

include ../../plugs.mk

user-install:
	cp *.$(EXT_SO) ~/.config/radare2/plugins
