# TEST
CC=gcc
PREFIX=/usr
HOST_OS=linux
VERSION=0.10.4
LIBDIR=/usr/lib
INSTALL_LIB=/usr/bin/install -m 755 -c
USEROSTYPE=auto

HAVE_PKGCFG_UNICORN=0
UC_CFLAGS=
UC_LDFLAGS=

R2_CFLAGS=-I/usr/include/libr
R2_LDFLAGS=-lr_core -lr_config -lr_cons -lr_io -lr_util -lr_flags -lr_asm -lr_debug -lr_hash -lr_bin -lr_lang -lr_io -lr_anal -lr_parse -lr_bp -lr_egg -lr_reg -lr_search -lr_syscall -lr_socket -lr_fs -lr_magic

HAVE_LIB_EWF=0
EWF_CFLAGS=
EWF_LDFLAGS=

#CFLAGS+=$(R2_CFLAGS)
#LDFLAGS+=$(R2_LDFLAGS)

ifeq ($(HOST_OS),darwin)
LIBEXT?=dylib
else
  ifeq ($(HOST_OS),windows)
    LIBEXT?=dll
  else
    LIBEXT?=so
  endif
endif

