# r2k

kernel module for radare2 r2k://

This module is part of radare2 (https://github.com/radareorg/radare2).

## Build

To compile this plugin just run `make` on your favourite Linux box.

```bash
$ make
```

To insert the module on modern kernels you need to:

* disable codesign (append `module.sig_enforce=0` in the /boot/grub.cfg cmdline)
* disable secure boot (in the BIOS/UEFI)

After this you may be able to run the following lines:

```bash
$ sudo rmmod r2kmod
$ sudo insmod r2kmod.ko
```

## Features

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
