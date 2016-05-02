#!/bin/sh
#
# testsuite for keystone assembler plugins
#
# author: pancake@nopcode.org
#
ks() {
	printf "Assembling: $3... "
	B=`rasm2 -a $1 -b $2 "$3" 2>/dev/null`
	if [ "$B" = "$4" ]; then
		echo "\033[32mOK\033[0m"
	else
		echo "\033[31mFAIL\033[0m  $B vs $4"
	fi
}

ks x86 32 "mov eax, 33" b821000000
ks x86 32 "mov rax, 33" ""
ks x86 64 "mov rax, 33" 48c7c021000000
ks x86 32 "int3" cc
ks x86 32 "int 3" cd03

ks arm 32 "bl 0x300" be0000eb
ks arm 32 "bpkt" 000000ea
ks mips 32 "addi t0, t0, 3" 03000821

ks arm' -e' 32 "bl 0x300" eb0000be
ks arm' -e' 32 "bpkt" ea000000
ks mips' -e' 32 "addi t0, t0, 3" 21080003
