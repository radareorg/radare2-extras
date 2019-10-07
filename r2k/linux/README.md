# r2k
kernel module for radare2

This module is going to be part of radare2 (https://github.com/radareorg/radare2).

It will work together with an userland program (https://github.com/radareorg/radare2/blob/master/libr/io/p/io_r2k.c)

This module allows to:

- Read from Kernel linear address
- Writes at Kernel linear address
- Read from User linear address
- Writes at User linear address
- Read from Physical address
- Write at Physical address
- Get kernel maps with their physical pages
- Read CPU regs
- Reads information from a pid
