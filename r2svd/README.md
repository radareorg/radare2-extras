SVD loader for r2
=================

https://github.com/radareorg/radare2/issues/15484

https://raw.githubusercontent.com/posborne/cmsis-svd/master/data/Atmel/AT91SAM9CN11.svd

Installation:
-------------
```
$ r2pm -i r2svd
```

or just `make install` in this directory

Usage:
------

```
$ r2 -m 0x400000 firmware.fw
> !r2svd

TexasInstruments
Nordic
NXP
Cypress
Fujitsu
Toshiba
Spansion
ARM_SAMPLE
Nuvoton
Freescale
Holtek
SiliconLabs
SiFive-Community
STMicro
Atmel

> !r2svd Holtek
ht32f125x.svd
ht32f175x.svd
ht32f275x.svd
> .!r2svd Holtek ht32f125x.svd
```
