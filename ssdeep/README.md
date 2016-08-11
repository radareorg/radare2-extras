ssdeep fuzzy hashing for radare2
===================================

How to install
------------------------

	$ r2pm -i ssdeep-lib
	$ r2pm -i ssdeep

Usage
-----

	$ r2 /bin/ls
    > ssdeep?
    ssdeep? - show help
    ssdeep[e|d] - calculate fuzzy hash for a block (esil/disasm)
    ssdeep custom_len
    ssdeep custom_len @address

