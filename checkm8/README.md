This is the r2 plugin to read/write memory using the checkm8 exploit.

1. Clone https://github.com/axi0mX/ipwndfu
2. Copy this file into the root directory of this repository
3. r2 -I r2io.py ipwndfu://
4. enjoy

NOTES

* This is very unstable, reading on unallocated regions results in device reboot
* Requires python3 .. so maybe better use @geohot's fork
