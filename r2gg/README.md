# Game Gear emulation with ESIL

`r2gg` connects radare2's Z80 ESIL backend to Game Gear hardware: Sega
cartridge banking, RAM, the color VDP, controls, interrupts, and stereo PSG
sound. It follows the `r2gb` command interface. The supplied Columns ROM
boots into gameplay and responds to Start through its title and menus.

## Build and run

Build radare2 with the Z80 ESIL changes in `libr/arch/p/z80/` first. Use an
optimized radare2 build (`CFLAGS="-O2 -g"`); an unoptimized build can run
below real time and starve audio even when the plugin is optimized. The
plugin needs the matching development headers and libraries from `pkg-config`.

```sh
make -j2
make install
r2 /tmp/columns.gg
```

Or load the local build without installing it (use the platform's plugin
extension, such as `.so` on Linux or `.dylib` on macOS):

```sh
r2 -i ./core_gg.dylib /tmp/columns.gg
```

Inside radare2:

```r2
r2gg?
r2gg play
```

`r2gg play` initializes the emulator if necessary, runs the cartridge,
prints the screen, polls input, and streams sound when r2au is available.
It starts directly at ROM address zero, skipping the firmware.

| Key | Button |
| --- | --- |
| `h`, `j`, `k`, `l` | Left, Down, Up, Right |
| `a`, `s` | Button 1, Button 2 |
| `f` or `F` | Start |
| `q` or Ctrl-C | Leave play mode |

Columns needs Start at the title, mode selection, and game settings screens.
Leaving play mode preserves emulated state and releases held buttons.
The Kitty keyboard protocol supports simultaneous holds and independent
releases. Other terminals use a 500 ms hold per press/repeat; set another
fallback with `r2gg play 200` (1–5000 ms). Keyboard mode, cursor, mouse,
and ESIL step-back configuration are restored on exit.

Set `scr.color=3` for RGB terminal output. The native half-block display
uses 160 columns and 72 rows, plus two status rows. Smaller terminals use
an area-averaged color image fitted to the available space. The view adapts
to resizing. `scr.color=0` uses an ASCII preview.

Play mode paces execution to the console's frame clock. Once the next frame's
CPU budget is complete, it waits for that frame's wall-clock deadline instead
of executing extra instructions. The audio producer retains its buffering lead.
Configure the maximum wait before entering play mode:

```r2
e gg.usleep=16000
r2gg play
```

`gg.usleep` is in microseconds, defaults to 16000, and accepts 0–1000000.
The actual sleep is capped at the next frame deadline, so larger settings do
not intentionally slow the console. Set 0 to disable sleeping and busy-wait
at the same emulated speed. Input is still polled during execution batches
and between waits. Pacing reduces idle CPU use; it cannot remove the CPU time
needed to emulate each frame. Manual ESIL stepping is unaffected.

## Stepping and inspection

```r2
r2gg
aes 3000000
r2gg status
r2gg screen
ar
```

`r2gg` initializes or resets the emulator. `aes`, `aesu`, and `aesue` run
the Z80 and peripherals together. Counts are execution steps, including
HALT waits and interrupt entries. Ctrl-C interrupts a long run. Startup can
take several million instructions; status reports CPU cycles and VBlank
frames. Nominal timing is 3,579,545 CPU clocks per second, 228 clocks per
scanline, and 262 scanlines per frame. Host performance can limit playback
speed.

The plugin owns `cmd.esil.step` and `cmd.esil.stepout` while active and
disables `esil.skipself` so polling loops work. Keep these hooks installed.
Visual mode caches ESIL expressions and register descriptors while checking
current instruction bytes, so bank switches and self-modifying RAM code remain
visible. Instruction fetches use a single IO read, splitting at the 16-bit
address boundary when necessary. The
step hook uses the same peripheral-aware execution path. Analysis hints,
ESIL pins, and step-back do not provide a reversible peripheral history.
Do not use them as a replacement for emulator state snapshots.

Held buttons can also be controlled explicitly:

```r2
r2gg keys 128
aes 20000
r2gg keys 0
aes 600000
```

The mask uses right=1, left=2, up=4, down=8, button 1=16, button 2=32,
and Start=128. Combine masks for simultaneous holds. The cartridge must
execute while a button is held, and a release is needed between presses.
The joypad and Start ports return active-low hardware values.

## Color display and memory

The VDP has 16 KiB VRAM, two 16-color palettes in 64-byte CRAM, and a
160×144 LCD viewport cropped from the 256×192 Mode 4 display at (48,24).
Each palette entry is a 12-bit RGB color, expanded to RGB24 for inspection.
The renderer handles tile planes, tile palettes, flips, scrolling, background
priority, sprites, sprite zoom, collision, and the eight-sprite scanline limit.
VDP reads use the hardware read buffer; control/data accesses reset the
command latch, and status reads acknowledge frame and line interrupts.

The framebuffer is 69,120 bytes of row-major RGB24 at `gg.framebuffer`
(`0x10000`), outside the CPU address space:

```r2
r2gg screen
e hex.cols=160
pri @gg.framebuffer!69120
wtf /tmp/gg.rgb 69120 @gg.framebuffer
```

`r2gg screen` always uses the native width and respects `scr.color`.
`pri`, `prig`, and `pris` can display the mapped pixels through the ordinary
radare2 image commands.

`r2gg maps` lists runtime mappings. The emulator has a separate IO bank
and a resident copy of the cartridge; the original ROM is preserved.
Reset reloads it, so edits to the source descriptor take effect on reset.

| Address | Runtime memory |
| --- | --- |
| `0000–03ff` | Fixed first 1 KiB of cartridge |
| `0400–3fff` | Sega mapper slot 0 |
| `4000–7fff` | Sega mapper slot 1 |
| `8000–bfff` | Sega mapper slot 2 or banked cartridge RAM |
| `c000–dfff` | 8 KiB work RAM |
| `e000–ffff` | Work RAM mirror; `fffc–ffff` also control the mapper |
| `10000–20dff` | Host RGB framebuffer |
| `30000–37fff` | Host PCM circular buffer |

Memory-mapped mapper writes and hardware port effects apply to ESIL
accesses. Raw `wx` writes bypass these effects. Keep `io.cache` disabled.
Z80 ESIL represents the separate 16-bit port bus at synthetic addresses
`0x1000000 + port`; this keeps ports distinct from CPU memory. The peripheral
model decodes the low eight port bits and the hardware mirrors.

`r2gg-` frees emulator maps and descriptors and restores the previous IO bank,
`io.va`, `esil.skipself`, and ESIL command hooks. Release the emulator before
changing architecture or closing its descriptors.

## Sound

The PSG models three tone channels and a noise channel, attenuation, latch
and data writes, Game Gear left/right routing, and the period-0/1 DC mode
used for volume-driven PCM voices such as Sonic's SEGA intro. Install r2au with `auq`
streaming support to hear audio during play mode. Missing audio support
does not prevent execution. To queue sound from ordinary stepping:

```r2
aes 100000
r2gg audio
r2gg audio-
```

`gg.audio` at `0x30000` is a 32,768-byte ring of signed little-endian 16-bit
stereo PCM at 44,100 Hz. `r2gg status` flushes pending samples and reports
cumulative bytes and the next write offset. Once wrapped, chronological
data starts at that offset and wraps around. Playback is asynchronous and
uses the same emulated CPU clock as video. Visual mode primes approximately
93 ms of PCM before playback and runs the producer 100 ms ahead of wall time
to absorb rendering and scheduling jitter.

## Validation and limitations

```sh
make test
make test-visual
make test-rom ROM=/tmp/columns.gg SNAPSHOTS=/tmp
make test-rom-long ROM=/tmp/columns.gg
make test-sonic ROM=/tmp/sonic.gg WAV=/tmp/sonic-intro.wav
make test-speed ROM=/tmp/columns.gg
R2AU_PLUGIN=../r2au/core_au.dylib make test-speed ROM=/tmp/columns.gg
```

The first target tests memory/banking, color rendering, ports, input, CPU
execution, HALT, and interrupts without a ROM fixture. The PTY tests cover
button mappings, simultaneous holds, release events, terminal restoration,
and native/scaled color output. The optional ROM target boots Columns,
presses Start through the menus, and checks framebuffer transitions;
`SNAPSHOTS` optionally exports RGB frames. It also reports elapsed time and
unpaced speed relative to the console clock. `test-speed` measures 12 seconds
of paced color playback in an 80×24 PTY and checks that it sustains real time;
set `R2AU_PLUGIN` to include actual audio playback. The long Columns test runs past its former reset point. The Sonic test
exports the intro as WAV when requested and verifies three lives, a clear
death flag, and a valid BCD clock after entering Green Hill. ROMs are not
included.
The CPU regression cases are in radare2's `test/db/esil/z80`, alongside
the existing Z80 assembler and analysis tests.

This is an experimental emulator rather than a cycle-accurate hardware
reference. It supports raw ROM sizes from 16 KiB to 4 MiB in 16 KiB banks
and the Sega mapper. Other mappers, firmware, serial/link emulation,
battery-save persistence, and SMS/TMS video modes are not implemented.
The model uses fixed NTSC scanline timing, approximate horizontal counters,
and scanline rendering rather than pixel-level VDP bus timing. PSG analog
filtering and exact noise phase are not modeled. CPU work adds broad base,
CB, ED, IX/IY, arithmetic/flag, block-transfer, and port support; repeated
index prefixes, unusual undocumented flag behavior, and block-I/O flags
need further hardware-suite coverage. IM 0 assumes the console's `RST 38h`
interrupt bus value; IM 1 and IM 2 are handled by the peripheral model.

References: [Sega Game Gear manuals](https://www.smspower.org/Development/GGOfficialDocs),
[Zilog Z80 manual](https://www.zilog.com/docs/z80/um0080.pdf),
[VDP registers](https://www.smspower.org/Development/VDPRegisters),
[Sega memory map](https://www.smspower.org/Development/MemoryMap), and
[PSG documentation](https://www.smspower.org/Development/SN76489).

A local Columns profile measured the same 939-frame sequence at 36.1 seconds
before tuning and 7.45 seconds afterward (2.1× real time without pacing),
with identical framebuffer hashes at all four checkpoints. The changes include
an optimized plugin build, cached register descriptors, batched instruction
fetch, removal of redundant ESIL register reads/size queries, and optimized
radare2 ESIL/register/IO/utility libraries. Paced color playback with r2au
sustained 1.01× real time over 12 seconds. These timings depend on the host
and build configuration; the commands above allow repeating the measurements.

## Debugging notes

See [the emulator notes](doc/README.md) for traced bugs, hardware details,
and the limits of the current model.
