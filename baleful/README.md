Baleful plugin
==============
This repository contains a baleful plugins for radare2.

Baleful was a challenge relased in picoctf.

* The asm plugin is completed.

* The anal plugin is completed.

Related Documentation
==============
* http://lolcathost.org/b/BalefulRadare_EN_part_1of2.pdf

	English writeup and plugin implementation

* http://lolcathost.org/b/BalefulRadare_ES_parte_1de2.pdf
	
	Spanish writeup and plugin implementation
Quick example
==============
For a correct VM execution its needed setup the register "r_data" to allocated memory for internal data manipulation.
Here its a example how to configure and execute the virtual code until a specific address:

r2 -a baleful -e io.cache=true bin/vm.cifrada.code
[0x00000000] o malloc://0x1024 0x100000;e asm.bits=32;dr r_data=0x100000;s 0x1000;dr pc=0x1000;aesu 0x1843

Directories
===========

* asm/

	Contains the asm plugin

* anal/

	Contains the anal plugin.      

* bin/

	Contains binary un-upx code and vm code.

Building
--------

Just type `make`.

Installation
------------

Running `make install`. will put those shared libraries in your
HOME's directory.
