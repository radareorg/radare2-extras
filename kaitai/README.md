Integrating r2 with Kaitai
==========================

Installation:

	$ r2pm -i kaitai-struct-compiler
	$ r2pm -i ksv
	$ r2pm -i r2kaitai

Demo Session:

	$ r2 /bin/ls
	> !r2kaitai
	archive/lzh
	archive/rar
	archive/zip
	common/vlq_base128_be
	common/vlq_base128_le
	executable/dos_mz
	executable/elf
	executable/java_class
	executable/mach_o
	...

	> !r2kaitai executables/mach_o

	(... ksv show goes here ...)
