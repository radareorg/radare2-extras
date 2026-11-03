# r2tama

Tamagotchi P1/P2 emulation inside radare2. `core_tama.c` connects the
E0C62 ESIL backend to the E0C6S46 hardware: RAM, timer interrupts,
buttons, a 32×16 LCD with eight icons, and the buzzer.

Build radare2 with the E0C62 architecture backend first, then:

```sh
make -j2
make install
make roms
r2 -q -c 'r2tama play' roms/p1.bin
r2 -q -c 'r2tama play' roms/p2.bin
```

`play` initializes the ROM automatically. Press **a**, **s**, **d** for the
physical **A**, **B**, **C** buttons. Press **m** to toggle mute; the status
line shows `mute=on` or `mute=off`. Muting stops queued playback immediately
and stays set when leaving and resuming play. Press **q** or Ctrl-C to leave
play mode.
The emulator runs at the 32,768 Hz oscillator rate. Kitty keyboard event
support enables simultaneous holds and independent releases. Other terminals
hold each press for 500 ms; `r2tama play 200` changes that fallback duration.
Enhanced quit keys exit on release, so their release sequence is consumed
before returning to r2's prompt. The terminal, cursor and keyboard protocol
are restored on exit. The display fits the terminal using braille cells and
shows all eight fixed pictograms, four above and four below the matrix.
Active pictograms are brighter and outlined; inactive ones remain dimly visible.

Install the optional r2au plugin for live speaker output. PCM is generated
and mapped even when playback is unavailable. Audio playback uses r2au's
asynchronous `auq` interface at 44,100 Hz, signed little-endian 16-bit stereo.

## Debugging

```r2
r2tama
r2tama?
aes 100000
r2tama status
r2tama screen
r2tama regs
r2tama maps
ar
ar 4
ar 8
r2tama keys 2
aes 1500
r2tama keys 0
aes 10000
```

`r2tama` resets; `r2tama-` frees the emulator. `aes`, `aesu` and `aesue`
execute the CPU and hardware together through `cmd.esil.step` and
`cmd.esil.stepout`. Keep those hooks installed while emulating. Counts are
execution steps, including HALT waits. The CPU's `pc` is a **byte address**:
the reset vector is `0x200`, corresponding to hardware word address `0x100`.
Branch operands remain hardware step numbers, and `np` holds the page/bank.
`x` and `y` contain 12-bit nibble addresses. `ar 4` shows their nibble aliases,
A/B, and F; `ar 8` shows SP, NP and the synthetic halted register.

Held-button masks are A=1, B=2, C=4, tap=8; combine bits for simultaneous
presses, then send 0 to release. Firmware must execute while a button is held.
B opens the clock screen after boot. Follow the original toy's clock-setting
sequence before waiting for the egg to hatch.

## Buffers and hardware registers

| r2 address | Contents |
| --- | --- |
| `00000–02fff` | Private ROM copy, LE16 words, read/execute |
| `10000–1027f` | 640 nibbles of RAM, one nibble per byte |
| `10e00–10e4f` | LCD memory, commons 0–7 |
| `10e80–10ecf` | LCD memory, commons 8–15 |
| `10f00–10f7f` | Memory-mapped hardware registers |
| `20000–205ff` | 32×16 row-major RGB24 framebuffer |
| `20600` | Eight icon bits |
| `21000–29fff` | 128×96 RGB24 screen with pictograms and a 3× LCD matrix |
| `30000–37fff` | 32,768-byte PCM ring buffer |

The Harvard data bus is represented at `0x10000 + nibble_address` so it
cannot overlap ROM instructions. Each data byte contains a value from 0 to
15. CPU accesses apply port side effects and interrupt-factor reads clear
the corresponding flags. Ordinary r2 reads inspect the stored values without
acknowledging interrupts. Raw `wx` writes bypass peripheral side effects;
use CPU instructions or `r2tama keys` for hardware actions. Keep `io.cache`
disabled. Runtime mappings live in a separate IO bank and preserve the source
ROM descriptor. Reset reloads the source ROM.

Every implemented hardware register has a `tama.hw.*` flag, including
`tama.hw.K0`, `tama.hw.EIT`, `tama.hw.PTL`, `tama.hw.LCDCTL`,
`tama.hw.BZFQ`, and `tama.hw.R4`. `r2tama regs` lists their names, addresses
and values. Region flags name the ROM, RAM, LCD, native framebuffer, composed screen,
icons and PCM.

Render or export the full screen with normal radare2 buffer commands:

```r2
e hex.cols=128
pri @tama.screen!36864
wtf /tmp/tama-screen.rgb 36864 @tama.screen

# The native matrix remains available separately.
e hex.cols=32
pri @tama.framebuffer!1536
px 1 @tama.icons
```

A lit LCD dot is white (`ffffff`), an unlit dot black (`000000`). The icon
byte is separate from the matrix; bit 0 corresponds to the first top icon,
bit 7 to the last bottom icon. These bits come from LCD electrodes, not from
menu selection guesses:

| Position | Pictogram | LCD electrode | LCD memory bit |
| --- | --- | --- | --- |
| Top 1 | Food | SEG8 / COM0 | `0xe10`, bit 0 |
| Top 2 | Light | SEG8 / COM1 | `0xe10`, bit 1 |
| Top 3 | Game | SEG8 / COM2 | `0xe10`, bit 2 |
| Top 4 | Medicine | SEG8 / COM3 | `0xe10`, bit 3 |
| Bottom 1 | Toilet | SEG28 / COM12 | `0xeb9`, bit 0 |
| Bottom 2 | Status | SEG28 / COM13 | `0xeb9`, bit 1 |
| Bottom 3 | Discipline | SEG28 / COM14 | `0xeb9`, bit 2 |
| Bottom 4 | Attention | SEG28 / COM15 | `0xeb9`, bit 3 |

Add `0x10000` to those nibble addresses to inspect them in r2. LCD all-on
and all-off controls also affect selection. The [pictogram assets](assets/icons/README.md)
are embedded, so no image library or asset files are needed at runtime.

`r2tama audio` queues recent PCM; `r2tama audio-` stops playback. Status
reports total produced PCM bytes and the next ring write offset. After
wrapping, chronological audio starts at that offset and wraps at the end.

## Firmware sources

Firmware images cannot be redistributed and are not included in this
repository. The entire `roms/` directory is ignored by Git. Only the script
that fetches and converts the publicly linked word lists is provided.

`scripts/fetch-roms.py` creates `roms/p1.bin` and `roms/p2.bin` locally from
the links in the [Pebble emulator README](https://github.com/StefanBauwens/Tamagotchi-Emulator-Pebble#getting-a-rom-url).
P1 is the first generation; P2 is the Japanese second generation.

These files are **expanded 12-bit instruction images, not raw ROM dumps**.
Each contains 6,144 12-bit words from a hexadecimal text list, zero-extended
to **little-endian 16-bit words** with the upper four bits clear. Each image
is 12,288 bytes; it is neither a physical dump nor a packed 12-bit stream.

Fetch, convert and checksum your local images with:

```sh
make roms
```

| File | SHA-256 |
| --- | --- |
| `p1.bin` | `48a716bbae6395ad8b5f43c1a6f57f84ce8abffcdfda0786007b75c2e3a35665` |
| `p2.bin` | `a1dfc57fef2bc5c0284600f086bfb94ed42795709ee0466779af2d9a7e7a5769` |

The converter validates the input grammar, word count, 12-bit range and
binary checksums before writing either file.

## Validation and limits

```sh
make test
make test-rom
make test-rom-long
make test-visual
```

The C suite checks assembler/disassembler round trips and executes every
valid instruction encoding over eight CPU/RAM states, checking for ESIL
traps and unbalanced stacks. Hardware tests cover LCD segment/icon
wiring, LCD overrides, active-low buttons, interrupt acknowledgement,
programmable and clock timers, HALT wakeup, stack wrapping, PCM, oscillator
switching, reset and cleanup. ROM tests boot both firmwares for 20 seconds,
check lit LCD pixels and interrupts, and verify that B changes the screen.
`test-rom-long` confirms the clock and continues each firmware for another
600 emulated seconds.
PTY tests cover the installed launch command for both ROMs, real-time pacing,
A/B/C input, simultaneous holds, independent releases and terminal restoration.
A separate interactive-prompt
regression sends delayed and fragmented Kitty `q` releases and checks that
the next command executes without function-key errors or leftover input.

The new architecture and register fix live in radare2's
`libr/arch/p/e0c62/` and `libr/reg/rvalue.c`. radare2 regression tests are
`test/db/asm/e0c62_16`, `test/db/esil/e0c62`, and the nibble-register unit
test in `test/unit/test_reg.c`. No ESIL engine change was necessary.
The timed input poll in `libr/cons/input.c` keeps raw mode active on timeout,
matching the successful-read path, so polling cannot briefly enable echo.

This is an experimental P1/P2 emulator, with instruction-cycle timing rather
than a gate-level model. Serial links, watchdog resets, buzzer envelopes and
one-shot sound, external programmable-timer clocks, analog LCD contrast,
save-state persistence and other Tamagotchi MCU variants are not implemented.
The stopwatch uses an averaged 100 Hz clock. The screen exposes the native
matrix, icon bits and a composed buffer containing all eight pictograms.
Analysis hints, ESIL pins and step-back do not maintain a reversible peripheral history.

References: [Epson E0C6S46 technical manual](https://download.epson-europe.com/pub/electronics-de/asmic/4bit/62family/technicalmanual/tm_6s46.pdf),
[TamaLib](https://github.com/jcrona/tamalib), and the
[Pebble emulator](https://github.com/StefanBauwens/Tamagotchi-Emulator-Pebble).
