# SCQ16: the data-space bases as flags.  Load it in a session on the program memory image: `. tools/scq16_flags.r2`.
# The data memory is LITTLE-endian (the instruction stream is big-endian): read its words with `e cfg.bigendian=false` or `pxw`
# on a little-endian view.  `ior`/`iow` address the I/O space by port index (base + offset), not by byte.  The flag sizes are
# the windows the bases span (the main DM up to the I/O window), not measured extents.
fs scq16
f scq16.dm_main 0x8000 @ 0x0
f scq16.io_window 0x2000 @ 0x8000
f scq16.dm2 0x20000 @ 0x40000
fs *
