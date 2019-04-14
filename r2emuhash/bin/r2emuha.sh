#!/bin/sh
# This script is suposed to be executed from r2

SDB=~/prg/radare2/shlr/sdb/src/sdb 
#r="r2 -1"
#r="rax2"
r="r2cmd"

walkbbs() {
	at=$1
	bbs=`$r afbq @ $at`
	for bb in $bbs ; do
		bbsz=`$r '?v $Fs @'$bb`
		echo "$bb  $bbsz"
	done
}

match() {
	export SDB=$SDB
	A="$1"
	if [ -z "$A" ]; then
		A=ls.sdb
	fi
	for B in db/*.sdb ; do
		if [ "$A" = "$B" ]; then
			continue
		fi
		AKEYS=`$SDB $A |cut -d = -f1`
		BKEYS=`$SDB $B |cut -d = -f1`
		for a in ${AKEYS} ; do
			for b in ${BKEYS} ; do
				if [ "$a" = "$b" ]; then
					N=`$SDB $A $a`
					M=`$SDB $B $a`
					echo "CC $A $N is similar to $B $M"
					break
				fi
			done
		done
	done
}


if [ -z "$R2PIPE_IN" ]; then
	if [ -z "$1" ]; then
		echo "Usage: r2emuha.sh [make|find] [file]"
		echo " $ r2emuha.sh make /bin/ls"
		echo " $ r2emuha.sh make /bin/sleep"
		echo " $ r2emuha.sh find ls.sdb"
	else
		case "$1" in
		"make")
			r2 -qAA -i $0 "$2"
			;;
		"find")
			match "$2"
			;;
		*)
			echo "Unknown command. Use: make or find."
			exit 1
			;;
		esac
	fi
	exit 0
fi

emuhash() {
	at=$1
	name=`$r fd@$at`
	$r 'drw 0' > /dev/null # reset register values to 0
	$r aeim > /dev/null # initialize vm and set SP, BP, PC
	$r 'dr??' > .r0
	$r "aef $at 2>/dev/null" > /dev/null
	$r 'dr??' > .r1
	diff -ru .r0 .r1 | grep -v PC | grep -e '^- ' -e '^+ ' > .d
	#cat .d
	crc32=`rahash2 -qqa crc32 .d`
	if [ "$crc32" = 00000000 ]; then
		printf "$at $crc32 $name   (ignored)\r"
	else  
		echo "$at $crc32 $name"
		echo "$crc32=$name" >> ${SDBTXT}
	fi
	rm -f .r0 .r1 .d
}

FILE=$(`$r i~^file` | grep bin | cut -d : -f 1)
NAME=db/`basename "$FILE"`
echo "FILE=$FILE"
echo "NAME=$NAME"
SDBBDS=${NAME}.sdb
SDBTXT=${SDBBDS}.txt

:> ${SDBTXT}
fcns=`$r aflq`
for a in $fcns ; do
	emuhash $a
done

$SDB ${SDBBDS} = < ${SDBTXT}
