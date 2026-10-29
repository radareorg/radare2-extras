# Game Boy emulation with ESIL

The Game Boy CPU decoder and ESIL expressions live in `libr/arch/p/gb/`.
The `ningb` binary loader describes cartridge banks and hardware memory.
The `r2gb` core plugin in `radare2-extras/r2gb/` connects ESIL execution to the
Game Boy peripherals.
It provides `r2gb` commands for setup, input, and status.

This is a DMG emulator intended for inspection and experimentation. It skips
the boot ROM and starts at cartridge entry point `0x100`. ROM-only and MBC1
cartridges are supported. `/tmp/tetris.gb` can boot and display its screens.
This is not a cycle-accurate emulator; limitations are listed below.

## Build and install

This plugin needs a current radare2 development build with the Game Boy and
ESIL fixes, plus r2au with the asynchronous `auq` playback interface.

Install with r2pm (which also installs the r2au dependency):

```sh
r2pm -ci r2gb
```

Or build this directory against the radare2 headers and libraries selected by
`pkg-config`:

```sh
make -j2
make install
```

Restart r2 after installation. `make uninstall` removes the plugin.
`R2PM_PLUGDIR` selects an alternative installation directory.

For local checks, `make test` runs the C integration and command tests.
`make test-visual` exercises the display, simultaneous buttons, and held-key
input through a PTY on Unix. These targets load the built plugin directly;
installation is not required. Set `R2` and `R2R` to select the executables.

## Start a cartridge

Open the ROM normally so the binary loader can identify it:

```sh
r2 /tmp/tetris.gb
```

Inside radare2:

```r2
r2gb?
r2gb
aes 1000000
r2gb status
```

`r2gb` selects the Game Boy architecture, initializes post-boot registers,
allocates hardware memory and a framebuffer, and selects a separate IO bank.
The cartridge is copied once into a private memory descriptor to avoid file
IO during execution. ROM bank switching changes map offsets within that
resident copy. The original descriptor and ROM file are preserved; cartridge
edits take effect on the next emulator reset. Calling `r2gb` again resets
the emulator.

Use the normal ESIL execution commands:

```r2
aes
aes 100000
ar
aesu 0x200
```

`aes N` repeats the single-step command N times and counts execution steps,
not frames. Instructions take different numbers of clock cycles; a halted
CPU or an interrupt entry also consumes a step.
The repeat prefix (`1000aes`) is equivalent. Counted stepping follows calls,
returns, and branches and runs the same peripheral hooks as a single `aes`.

Ctrl-C interrupts long runs. Use `r2gb status` to inspect accumulated cycles
and VBlank events. Run additional steps if the cartridge is still starting.

The plugin installs the existing `cmd.esil.step` and `cmd.esil.stepout` hooks.
Keep those hooks installed while emulating. They advance the peripheral clock,
handle HALT, delay EI, and deliver interrupts. The plugin also disables
`esil.skipself` so polling loops and HALT can hold the PC. Direct evaluation
of a raw ESIL expression with `ae` is not an emulated instruction step.

For frame-oriented stepping, define an ordinary radare2 macro:

```r2
(gbframe;aesue 0xff44,[1],144,-;aesue 0xff44,[1],144,-,!)
.(gbframe)
100.(gbframe)
```

The first condition leaves VBlank if already there; the second runs until
`LY` is 144 again. The macro waits for the cartridge to enable its LCD. A
cartridge that keeps its LCD disabled will require Ctrl-C to stop this wait.

## Play mode

```r2
r2gb play
```

This initializes the cartridge if needed, continuously executes ESIL, renders
the display, streams sound through r2au when available, and polls the keyboard
without waiting for a keypress. A terminal
of at least 160 columns and 74 rows uses the exact native half-block image
from `r2gb screen`. Smaller terminals use braille cells (two by four pixels)
to retain more detail: 80 columns and 38 rows can show every original pixel
position. Smaller windows use area-filtered scaling rather than dropping
individual pixels. The view adjusts when the terminal is resized.

| Key | Button |
| --- | --- |
| `h`, `j`, `k`, `l` | Left, Down, Up, Right |
| `a`, `s` | A, B |
| `D`, `F` | Select, Start |
| `q` | Leave play mode |

`d`/`D` and `f`/`F` select Select and Start. Visual mode requests the Kitty
[keyboard event protocol](https://sw.kovidgoyal.net/kitty/keyboard-protocol/),
including releases for ordinary letters. With a
supporting terminal, the status line says `input=press/release`: each button
stays held until its own key is released. Multiple buttons can be held and
released independently, without depending on keyboard repeat.

Terminals without release events show `input=timed (500 ms)`. Each press or
repeat extends that button's hold by 500 milliseconds of real time. This
bridges the usual initial repeat delay, but cannot exactly reproduce physical
key releases or arbitrary simultaneous holds. Adjust the fallback duration
with `r2gb play 200`, for example, for shorter taps. The range is 1–5000 ms.
The hold duration does not change with emulation speed. Supporting terminals
use real releases regardless of this fallback setting. Keyboard protocol
settings are restored on exit.

Quitting releases all buttons and preserves emulated state, so normal stepping and inspection can
continue. Ctrl-C also exits. Visual mode temporarily disables ESIL step-back
recording and restores that setting, the cursor, mouse, and terminal mode
on exit. It requires `scr.interactive=true`.

Visual mode uses the decoder's ESIL with cached instructions and register
descriptors. It omits analysis hints and ESIL pins; use normal `aes` commands
for those debugging features. Cached instructions are checked against their
current bytes so bank switches and self-modifying RAM code remain visible.
Audio is submitted in chunks with roughly 50 ms of buffering to absorb
rendering and scheduling delays.

Play mode paces execution to the console's frame clock. Once the next frame's
CPU budget is complete, it waits for that frame's wall-clock deadline instead
of executing extra instructions. The audio producer retains its buffering lead.
Configure the maximum wait before entering play mode:

```r2
e gb.usleep=16000
r2gb play
```

`gb.usleep` is in microseconds, defaults to 16000, and accepts 0–1000000.
The actual sleep is capped at the next frame deadline, so larger settings do
not intentionally slow the console. Set 0 to disable sleeping and busy-wait
at the same emulated speed. Input is still polled during execution batches
and between waits. Pacing reduces idle CPU use; it cannot remove the CPU time
needed to emulate each frame. Manual ESIL stepping is unaffected.

## Sound and music

Install the r2au plugin with asynchronous PCM streaming support (`auq?`):

```sh
r2pm -ci r2au
```

`r2gb play` opens stereo output automatically. It generates sound from the
same emulated clock as the CPU and display, and queues PCM without blocking
keyboard input. Leaving play mode stops playback and closes its output
device. If r2au is missing, too old, or cannot open a device, emulation
continues without playback. Restart r2 after updating a loaded plugin.

To audition sound produced by ordinary ESIL stepping:

```r2
aes 100000
r2gb audio
r2gb audio-
```

`r2gb audio` queues pending samples and returns immediately. Repeat it after
more steps. `r2gb audio-` stops playback; `r2gb-` also releases it. The APU
runs during ordinary stepping even when playback is disabled.

`gb.audio` is a 32,768-byte circular buffer at `0x30000`. Samples are signed
16-bit little-endian stereo at 44,100 Hz, interleaved left then right. It
retains approximately 186 ms of recent sound. `r2gb status` reports total
PCM bytes produced (`audio`) and the next write offset (`offset`). When the
buffer has wrapped, chronological samples run from that offset to the end,
then from the beginning to that offset. Before it wraps, only the first
`audio` bytes are valid. Status flushes any pending samples into mapped memory.
The buffer can be inspected with ordinary print and export commands:

```r2
r2gb status
pxh 64 @gb.audio
wtf /tmp/gb.pcm 32768 @gb.audio
```

Both pulse channels, channel 1 sweep, wave RAM, noise, length counters,
volume envelopes, DAC control, NR50 volume, and NR51 stereo routing are
implemented. Audio register side effects require ESIL memory accesses;
raw `wx` edits only the backing IO memory. The APU continues while the CPU
is halted and while the LCD is off. Live playback speed depends on the host
keeping up with emulation; this is not an audio accuracy reference emulator.

## Print the framebuffer

Use the plugin command to display the screen at its native width:

```r2
r2gb screen
```

It reads the framebuffer directly, uses `scr.color`, and always renders
160 pixels per row, independently of `hex.cols` and the current seek.
With color enabled, an upper half-block character displays two vertical
pixels per terminal cell. The image occupies 160 columns and 72 rows.
Use a terminal at least 160 columns wide to avoid line wrapping.

The framebuffer is ordinary mapped memory at `0x10000`, named
`gb.framebuffer`. It contains 160 × 144 pixels in row order, three bytes per
pixel (RGB24), for a total of 69,120 bytes. Each channel contains the same
grayscale value: 255, 170, 85, or 0 after applying the Game Boy palettes.

```r2
e hex.cols=160
pri @0x10000!69120
```

For grayscale terminal output:

```r2
prig @0x10000!69120
```

For sixel output in a supporting terminal:

```r2
pris @0x10000!69120
```

The `!69120` modifier supplies the image's byte length for this command.
`hex.cols` supplies its width. Changing the normal hexdump block size is not
necessary. The same memory can be inspected or exported:

```r2
px 48 @0x10000
wtf /tmp/gb.rgb 69120 @0x10000
```

`hex.cols` specifies the number of source pixels per row; it does not scale
the image. A value other than 160 reinterprets the framebuffer's row layout.
`pri` and `prig` use the same upper/lower half-block layout for color output;
`prig` maps RGB values to the terminal's grayscale palette. With `scr.color=0`,
`r2gb screen` and plain `pri` use a lossy ASCII preview.

The framebuffer lies outside the CPU's 16-bit address space. It is a host-side
view of the LCD output. A Game Boy program writes tile data, tile maps, OAM,
and LCD registers; the peripheral model converts these into framebuffer rows.
It does not expect the cartridge to draw RGB pixels directly.

## Press and release buttons

`r2gb keys N` sets a bit mask of held buttons. It stays active until replaced.

| Button | Mask |
| --- | ---: |
| Right | 1 |
| Left | 2 |
| Up | 4 |
| Down | 8 |
| A | 16 |
| B | 32 |
| Select | 64 |
| Start | 128 |

For a Start press:

```r2
r2gb keys 128
aes 20000
r2gb keys 0
aes 100000
pri @0x10000!69120
```

The cartridge must execute while the button is held to sample it. Release
between presses because menus often respond to a new press rather than a
held button. For Tetris, press Start at the title screen and again as needed
to confirm the game type and level. Combine masks to hold multiple buttons:

```r2
r2gb keys 24
aes 20000
r2gb keys 0
```

This holds Down and A. The emulated joypad register at `0xff00` still obeys
the hardware's row-selection bits and active-low button convention.

## Memory and banking

```r2
r2gb maps
```

This lists the emulator's IO bank and runtime mappings, including address
ranges, permissions, backing descriptors, cartridge offsets, and the
framebuffer. The ROM/RAM offsets reflect the current MBC1 selection.
`gb.ram` is the shared allocation backing VRAM, work RAM, OAM, and IO ports;
`gb.echo` aliases work RAM and `gb.eram` supplies banked cartridge RAM.

Use `omb` and `om` to inspect IO banks and maps. The plugin's `gameboy` IO
bank presents the CPU address space, while the loader's original bank remains
available for static analysis of all cartridge banks.

| Address | Runtime mapping |
| --- | --- |
| `0000–3fff` | Fixed ROM window; switchable upper bank bits in MBC1 mode 1 |
| `4000–7fff` | Switchable ROM window |
| `8000–9fff` | Video RAM |
| `a000–bfff` | Cartridge RAM, subject to controller enable and banking |
| `c000–dfff` | Work RAM |
| `e000–fdff` | Alias of work RAM at `c000–ddff` |
| `fe00–fe9f` | Sprite attribute memory (OAM) |
| `fea0–feff` | Unusable memory; ESIL reads return `ff` |
| `ff00–ff7f` | IO registers |
| `ff80–fffe` | High RAM |
| `ffff` | Interrupt enable register |
| `10000–20dff` | Host RGB framebuffer |
| `30000–37fff` | Host stereo PCM circular buffer |

MBC1 control writes from ESIL update the ROM/RAM map offsets. The CPU keeps
a 16-bit PC, so both instruction fetches and data reads see the selected
cartridge bank. No ROM copying is needed when switching banks. Writes to
the ROM windows control the MBC instead of overwriting ROM bytes.

Memory-mapped hardware behavior applies to ESIL accesses. A raw `wx` or `px`
command accesses the backing memory directly and can bypass register masks
or hardware side effects. Execute cartridge instructions to exercise MBC,
joypad, divider, timer, or DMA behavior. Keep `io.cache` disabled to avoid
stale cached ROM data after bank switches.

The renderer reads VRAM and OAM at scanline boundaries, handles background
and window tile maps, scrolling, signed tile indices, sprite palettes,
flipping, transparency, priority, and 8×16 sprites. It writes each visible
row into the framebuffer. VBlank and LCD status interrupt requests are
generated from the LCD clock, independently of whether the screen is printed.

## Release the emulator

```r2
r2gb-
```

This releases the emulator's maps and memory, restores the previous IO bank
and ESIL hooks, restores `io.va` and `esil.skipself`, and removes the framebuffer
and audio flags. It does not close the ROM.
Release the emulator before changing architecture or closing its cartridge
or memory descriptors. Reinitializing with `r2gb` creates fresh state.

## Accuracy and remaining work

The CPU fixes include CB shifts and rotates, bit-set masks, accumulator rotate
flags, ADC/SBC carries, 16-bit arithmetic flags, decimal adjustment, POP AF,
post-decrement loads, jumps into RAM, STOP length, and instruction timings.
Assembler fixes cover truncated input normalization and several incorrect
encodings and instruction lengths. These are covered by `test/db/asm/gb`
and `test/db/esil/gb`; loader tests are in `test/unit/test_bin_ningb.c`.
Plugin integration tests are in `tests/test_core_gb.c`,
`tests/db/gb_peripherals`, and `tests/test-gameboy-visual.py`.

The peripheral model is deliberately limited:

- DMG only; CGB-only cartridges and controllers other than ROM/MBC1 are rejected.
- No serial link, RTC, battery-save persistence, or boot ROM.
- Audio models the DMG channels, but not all analog filtering, active wave-RAM
  access restrictions, retrigger corruption, or envelope-write hardware quirks.
- LCD mode 3 has a fixed duration; sprite/window stalls and pixel FIFO effects
  are not modeled. Window line counting is approximated from its position.
- VRAM/OAM access restrictions and DMA CPU bus stalls are not modeled.
- Timer overflow reload is immediate rather than delayed by four clocks.
- STOP is treated as a halted CPU; low-power and speed-switch behavior is absent.
- ESIL step-back does not restore peripheral counters, controller state, or
  previously rendered pixels.
- The assembler still lacks some load forms. For example, `ld a, [bc]` and
  `ld sp, hl` currently fall back to immediate loads, and `ldi a, [hl]` is
  rejected. These affect patching ROMs, not decoding or executing those bytes.

This work does not establish that every Game Boy emulation bug has been found.
Hardware test ROMs are needed to extend timing accuracy and validate more games.
Binary fixtures belong in `radare2-testbins`, not this repository.

References: [Pan Docs](https://gbdev.io/pandocs/),
[SM83 instruction descriptions](https://rgbds.gbdev.io/docs/gbz80.7),
and [opcode tables](https://gbdev.io/gb-opcodes/optables).
