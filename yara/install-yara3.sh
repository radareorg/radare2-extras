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

if [ ! -d yara3.git ]; then
	git clone https://github.com/plusvic/yara.git yara3.git|| exit 1
fi
cd yara3.git || exit 1
# last commit in git
git pull
sh bootstrap.sh
./configure --prefix=${PREFIX} || exit 1
${MAKE} -j8 || exit 1
${SUDO} ${MAKE} install
