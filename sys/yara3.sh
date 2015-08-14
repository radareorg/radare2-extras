#!/bin/sh
export PKG_CONFIG_PATH="/opt/local/lib/pkgconfig:/usr/lib/pkgconfig:${PKG_CONFIG_PATH}"
pkg-config --libs yara
if [ $? != 0 ]; then
	yara/install-yara3.sh
fi
SUDO=sudo
cd yara/yara3
./configure --prefix=/usr || exit 1
make clean
make || exit 1
if [ "`id -u`" = 0 ]; then
	${SUDO} make install || exit 1
else
	echo "[yara3] installing at home"
	mkdir -p ~/.config/radare2/plugins
	cp -f core_yara3.{dylib,dll,so} ~/.config/radare2/plugins 2> /dev/null
fi
