#!/bin/sh
FILE=$1
type addr2line > /dev/null 2>&1
if [ $? = 0 ]; then
	ADDRS=`objdump -d "$FILE" |grep :| grep -v 0000000| grep -v Disas|cut -d : -f1` 
	addr2line -pa -e "$FILE" $ADDRS | sed -e 's,:,,' -e 's,^,CL ,' | grep -v '?'
else
	echo "Unable to find 'addr2line' executable in PATH"
	exit 1
fi
