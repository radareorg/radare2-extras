# Game Gear hardware and ESIL debugging curiosities

## A familiar CPU name is not a compatible Game Boy CPU

The Game Gear uses a Z80. The monochrome Game Boy uses the SM83, which has
a related instruction set but different flag positions and no Z80 IX/IY or
alternate-register banks. The old radare2 Z80 profile used Game Boy-style
flag positions. Correcting that profile was required before instructions
could drive either game reliably.

A useful comparison is the flags byte. Z80 carry is bit 0, subtract bit 1,
parity/overflow bit 2, half-carry bit 4, zero bit 6, and sign bit 7. DMG's
flags occupy bits 4–7 in a different order. See the two architecture plugins
in radare2 and [the Game Boy notes](../../r2gb/doc/cpu-and-esil.md).

## A flag can be correct briefly and then get masked away

Instruction comparison during the Sonic investigation found two extra
Z80 defects. CPL set H and N, then rebuilt F using a mask that discarded H.
CCF copied the old carry into H, then discarded H in a similar final mask.
Both therefore disagreed with a reference CPU despite producing the expected
accumulator and carry values.

CPL now preserves S/Z/PV/C, sets H/N, and derives undocumented bits 3/5
from the complemented accumulator. CCF's final mask retains H. Targeted
cases are in radare2's `test/db/esil/z80`. These are confirmed instruction
fixes; finding them is not proof that either caused every reported Sonic
symptom.

## Cartridge banking and CPU addresses are separate coordinates

The Sega mapper selects three 16 KiB windows. The first 1 KiB of ROM stays
fixed. Work RAM at `c000–dfff` is mirrored at `e000–ffff`, and writes to
`fffc–ffff` also control the mapper.

A runtime PC such as `7c16` is consequently not a unique file offset. Sonic
switches banks around its sound code. Disassembling the flat ROM at file
offset `7c16` can show entirely different instructions from the running
sample player. Record mapper state with instruction traces, and decode from
the active emulator bank. `r2gg maps` prints current ROM offsets.

## The framebuffer does not live in VRAM

The Z80 writes the VDP through ports. The model keeps 16 KiB of tile VRAM
and 64 bytes of palette RAM, and renders a 160×144 crop from the Mode 4
screen. `gg.framebuffer` is a host-side RGB view at `10000`, outside the
CPU's 16-bit address space. Editing those RGB bytes does not edit tiles.
The next rendered scanline can replace such edits.

Z80 ports use a separate synthetic ESIL address region at `1000000+port`.
Without that separation a port such as `be` would collide with ROM address
`00be`. Ordinary `wx` accesses do not reproduce VDP control-latch or read-
buffer side effects; execute an IN/OUT instruction to test them.

## Frame pacing and correctness answer different questions

The model clocks a scanline every 228 CPU cycles and a frame every 262
scanlines. `gg.usleep` limits the host wait after a frame budget is complete.
It does not add emulated cycles. Audio runs ahead with a queue so a short
terminal-rendering stall need not become an underrun.

The performance investigation found repeated register-name lookups and
four independent IO reads per instruction fetch. Cached descriptors and a
batched fetch removed those costs. An unoptimized radare2 build was another
large factor. Better throughput and buffering did not fix the Columns BCD
bug or Sonic's incorrectly generated PCM; those needed semantic changes.

## Reference comparison is a diagnostic, not a replacement engine

A temporary diagnostic compared executed Sonic instructions against
[floooh/chips Z80](https://github.com/floooh/chips/blob/master/chips/z80.h),
replaying data reads to avoid acknowledging VDP status twice. It compared
PC, stack, register pairs, alternate registers, and documented arithmetic
flags. The temporary checker is not a shipped dependency. Undocumented
flags, block-IO flag details, and peripheral timing require separate care.
