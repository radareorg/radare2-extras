#!/bin/sh
PREFIX=/usr
MAKE=make
SUDO=sudo


# https://raw.githubusercontent.com/sroberts/peid4yara/master/peid.yar
#if [ ! -f shlr/yara/peid.yar ]; then
#(
#	cd shlr/yara
#	wget -c http://radare.org/get/peid.yar.gz
#	gunzip peid.yar.gz
#)
#fi

if [ ! -d yara2.git ]; then
	git clone https://github.com/plusvic/yara.git yara2.git|| exit 1
fi
cd yara2.git || exit 1
# working yara2 version
git reset --hard 880c268ce0b98046a476784c412d9e91573c8a08
sh bootstrap.sh
./configure --prefix=${PREFIX} || exit 1
${MAKE} -j8 CFLAGS=-DYYDEBUG=0 || exit 1
${SUDO} ${MAKE} install

