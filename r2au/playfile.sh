#!/bin/sh
if [ -z "$1" ]; then
	echo "Usage: playfile.sh [file]"
	exit 1
fi
r2 -qc aui -c 'b $s;au.' -n $*
