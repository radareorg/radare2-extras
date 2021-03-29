#!/bin/sh

A="$1"
M="`echo $2 |tr '[a-z]' '[A-Z]'`"

R2_USER_PLUGINS=$(r2 -H R2_USER_PLUGINS)
if [ -z "$A" ]; then
	echo "Usage: iref [arch] ([insn])"
	if [ ! -d iref-db ]; then
		 cd "$R2_USER_PLUGINS" || exit 1
	fi
	cd iref-db 
	ls |sed -e 's,.sql,,'
	exit 1
fi
if [ ! -f "iref-db/$A.sql" ]; then
	cd "$R2_USER_PLUGINS" || exit 1
	if [ ! -f "iref-db/$A.sql" ]; then
		echo "Cannot load $A"
		exit 1
	fi
fi

if [ -z "$M" ]; then
	echo "select mnem from instructions" | sqlite3 -init iref-db/$A.sql | tr 'A-Z' 'a-z'
else
	echo "select description from instructions where mnem = '$M'" | sqlite3 -init iref-db/$A.sql
fi
