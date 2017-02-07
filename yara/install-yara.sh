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

if [ ! -d yara.git ]; then
	#git clone https://github.com/plusvic/yara.git yara.git|| exit 1
	git clone https://github.com/VirusTotal/yara yara.git|| exit 1
fi
cd yara.git || exit 1
# last commit in git
git pull
sh bootstrap.sh
# brew
export CFLAGS="-I/usr/local/opt/openssl/include"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
./configure --prefix=${PREFIX} || exit 1
${MAKE} -j8 || exit 1
${SUDO} ${MAKE} install
