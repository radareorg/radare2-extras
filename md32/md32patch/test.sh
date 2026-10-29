#!/bin/sh
# Verifica el parche con un vector sintético (sin código de fabricante).
r2 -q -a md32 -e cfg.bigendian=true -e asm.cpu=usip -c "pd 8 @ 0" test-vector.bin
