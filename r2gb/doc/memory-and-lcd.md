# Memory aliases, mapper registers, and LCD pixels

## ROM is copied; a bank switch changes the view

`r2gb` copies the cartridge into a resident descriptor and gives the CPU a
separate IO bank. MBC1 register writes change map offsets instead of copying
a ROM bank on every switch. The original cartridge descriptor remains
available for analysis. Reset reloads its edits into the resident image.

A CPU address in the switchable window is not a stable cartridge offset.
Record both PC and bank selection when diagnosing code reached only after
a menu transition. `r2gb maps` prints the active map offsets.

## Echo RAM is an alias

The work-RAM echo is mapped to the same storage as work RAM. Keeping a
second independent copy and occasionally synchronizing it would let CPU
reads observe inconsistent values. Tests explicitly write through both
addresses and check the other view.

Memory-mapped peripheral writes are different from raw IO edits. For
example, ESIL mapper writes update banking and a DMA register write copies
OAM data. `wx` only changes backing memory and can bypass these effects.
That distinction also matters for joypad selection and APU registers.

## Tile memory is not an RGB image

The DMG renderer decodes two tile bitplanes, chooses the background/window
map, applies scrolling and signed tile indices, and composes sprites using
palettes, priority, and flip bits. The final grayscale shade is expanded to
three identical RGB channels.

`gb.framebuffer` at `10000` is 160×144×3 bytes. It is a host-side view outside
the CPU address space. `pri @gb.framebuffer!69120` prints that view when
`hex.cols=160`; changing `hex.cols` reinterprets row width, rather than
changing the emulated LCD resolution.

The terminal's half-block display packs two vertical pixels into each
character cell. Compact Game Boy views use braille and grayscale filtering;
the Game Gear view instead preserves RGB through scaled half-block cells.

## Scanline accuracy has explicit limits

The current LCD model uses a fixed mode-3 duration rather than modeling the
pixel FIFO and variable sprite/window stalls. VRAM/OAM access restrictions
and DMA CPU stalls are not implemented. Timer overflow reload is immediate.
A correct screenshot therefore does not establish timing accuracy for a
hardware test ROM.

See `gameboy_mem_write`, `gameboy_scanline`, and `gameboy_tick` in
[`core_gb.c`](../core_gb.c), and the memory/LCD tests in
[`test_core_gb.c`](../tests/test_core_gb.c).
