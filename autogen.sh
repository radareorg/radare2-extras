#!/bin/sh
#
# Look for the 'acr' tool here: https://github.com/radare/acr
# Clone last version of ACR from here:
#  git clone https://github.com/radare/acr
#
# -- pancake
files=`find . -name configure.acr`
for a in ${files}; do
	echo "[+] $a"
	( cd `dirname $a` ; acr -p )
done
if [ -n "$1" ]; then
	echo "./configure $@"
	./configure $@
fi
