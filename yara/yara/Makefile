PWD=$(shell pwd)
R2VERSION=@R2VERSION@
DESTDIR=
PREFIX=/usr/local
HOST_OS=linux
LIBDIR=/usr/local/lib
INSTALL_LIB=/usr/bin/install -m 755 -c

#LIBYARA_CFLAGS=@LIBYARA_CFLAGS@
#LIBYARA_LDFLAGS=@LIBYARA_LDFLAGS@
LIBYARA_CFLAGS=
LIBYARA_LDFLAGS=-lyara
R2_CFLAGS=-I/usr/include/libr
R2_LDFLAGS=-lr_core -lr_fs -lr_debug -lr_hash -lr_anal -lr_search -lr_egg -lr_crypto -lr_config -lr_bin -lr_magic -lr_io -lr_asm -lr_parse -lr_syscall -lr_reg -lr_lang -lr_cons -lr_flag -lr_socket -lr_bp -lr_util
YR_CFLAGS=
YR_LDFLAGS=-lyara

CFLAGS+=${R2_CFLAGS} ${LIBYARA_CFLAGS} ${YR_CFLAGS}
LDFLAGS+=${R2_LDFLAGS} ${LIBYARA_LDFLAGS} ${YR_LDFLAGS}
CFLAGS+=-I. -fPIC
LDFLAGS+=-shared

ifneq ("$(wildcard ../../options.mk)","")
include ../../options.mk
endif

MOD=core_yara

all: $(MOD).$(LIBEXT)

$(MOD).$(LIBEXT): ${MOD}.o
	${CC} ${MOD}.o ${CFLAGS} ${LDFLAGS} -o ${MOD}.${LIBEXT}

clean:
	rm -f ${MOD}.o ${MOD}.${LIBEXT}

mrproper: clean
	rm -f Makefile

install:
	${INSTALL_LIB} ${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/${MOD}.${LIBEXT}
	cp -rf ../rules-yara3/ $(R2PM_USRPLUGIN_DIR)/

symstall:
	ln -fs ${PWD}/${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/$(MOD).$(LIBEXT)
	rm -rf $(R2PM_USRPLUGIN_DIR)/yara
	ln -fs $(PWD)/../rules-yara3 $(R2PM_USRPLUGIN_DIR)/rules-yara3

uninstall:
	rm -f ${R2PM_USRPLUGIN_DIR}/$(MOD).$(LIBEXT)
	rm -rf ${R2PM_USRPLUGIN_DIR}/rules-yara3
	rm -rf ${R2PM_USRPLUGIN_DIR}/yara
