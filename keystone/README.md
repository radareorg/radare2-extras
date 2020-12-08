rizin-keystone
================

This repository contains the source code for the keystone
assembler plugins for rizin.

How to install
--------------

The plugins will be installed at ~/.config/rizin/plugins

	$ make
	$ make install

To uninstall them just:

	$ make uninstall

How to use it?
--------------

	$ rz-asm -L | grep .ks
	a___  16 32 64   arm.ks      BSD     ARM keystone assembler
	a___  32         hexagon.ks  BSD     Hexagon keystone assembler
	a___  16 32 64   mips.ks     BSD     MIPS keystone assembler
	a___  32 64      ppc.ks      BSD     powerpc keystone assembler
	a___  32 64      sparc.ks    BSD     sparc keystone assembler
	a___  32         sysz.ks     BSD     SystemZ keystone assembler (S390X)
	a___  16 32 64   x86.ks      BSD     x86 keystone assembler

	$ rz-asm -a x86.ks -b 32 int3
	cc
