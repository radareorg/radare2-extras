# MD32 architecture plugin

Native radare2 `RArchPlugin` for the MediaTek MD32 **MS15E30** ISA. The decoder
covers all **258 encoding forms** in the public vendor disassembler, including
16/32-bit instructions, packed instruction pairs, DSP operations, control
registers, and hardware-loop setup. It has no runtime dependency on Python,
Ghidra, Capstone, or vendor binutils.

The **uSIP** binaries use a different, VLIW-packet encoding. Select the `usip`
CPU for these (`e asm.cpu=usip`); see [uSIP mode](#usip-mode).

## Build and use

Requires radare2 development headers/libraries, `pkg-config`, a C compiler, and
make. Tested with radare2 6.2.5 on macOS arm64 and 6.2.2 on Linux x86-64
(against 6.2.2 the optional `tools/md32-run` runner does not build because
`r_esil_set_fault` is missing from that release: build the two plugins with
`make arch_md32.so asm_md32.so`).

```sh
make
make install
r2 -a md32 -b 32 -e cfg.bigendian=true firmware.be.bin
```

`make install` copies the architecture and assembly parse plugins to
`r2 -H R2_USER_PLUGINS`. Override `R2_PLUGIN_PATH` to choose another location.
`make uninstall` removes both.
Without installation, load the built library using `L /absolute/path/arch_md32.dylib`
inside r2 (`.so` on Linux), then set `e asm.arch=md32`.

For pseudocode display, enable `e asm.pseudo=true`. The `md32` assembly parser
is selected automatically with `asm.arch=md32`; select it explicitly with
`e asm.parser=md32` if needed. Without installation, load `asm_md32.dylib`
alongside `arch_md32.dylib` before selecting the architecture.

The parser covers scalar moves, arithmetic, bit operations, signed/unsigned
comparisons, calls, jumps and Harvard data-memory accesses. For example,
`lw r2, (r1+=0x8)` becomes `r2 = dmem32[r1]; r1 += 0x8`. Signed byte/halfword
loads use `sext8`/`sext16`; packed pairs display as `parallel { ...; ...; }`.
Delayed control flow and unresolved DSP operations retain their assembly text.
In `usip` mode the same rules apply to the uSIP mnemonics (`ld.w r0, [r8+0x4]`
becomes `r0 = dmem32[r8 + 0x4]`, `bnez r15, 0x418` becomes
`if (r15 != 0) goto 0x418`); format-only `.xxx` forms and `.unit` tails keep
their text. This is a display parser; it does not add instruction encodings or
ESIL semantics.

Instructions use big-endian byte order and two-byte alignment. Older VPU/DSP
blobs store the instruction stream in reversed **four-byte storage words**.
Normalize those files before opening them:

```sh
python3 tools/swap_words.py vpu_p.bin firmware.be.bin
```

This is not ordinary per-instruction byte swapping: a four-byte storage word
may contain two instructions or part of an instruction crossing its boundary.
Do not apply this conversion to the already big-endian uSIP samples.

## Supplied uSIP samples

```sh
r2 -a md32 -b 32 -e cfg.bigendian=true -c 'e asm.cpu=usip' \
  -m 0x400e0000 third_party/r2pkg/bin/usip_sec0.bin
r2 -a md32 -b 32 -e cfg.bigendian=true -c 'e asm.cpu=usip' \
  -m 0x1ca34000 third_party/r2pkg/bin/usip_ddr.bin
```

Optional symbol flags, generated directly from the supplied inventory:

```sh
python3 tools/usip_symbols.py --section sec0 > /tmp/usip-sec0.r2
python3 tools/usip_symbols.py --section ddr > /tmp/usip-ddr.r2
```

Load the corresponding script with `. /tmp/usip-sec0.r2` or
`. /tmp/usip-ddr.r2`. The first 0x400 bytes of sec0 are the vector table;
use the symbol inventory to choose code entry points. These are supplied load
aliases; the reset-vector conflict reported by `tools/analyze_firmware.py`
means they are not a validated boot memory map.

## uSIP mode

`e asm.cpu=usip` selects the decoder for the **uSIP** variant of the MD32 family
(VLIW execute packets of 16-bit units). The instruction set is described by the
table `isa/usip_isa.json` (386 forms, generated into `usip_opcodes.h` by
`tools/gen_usip_tables.py`) and by the packet model implemented in
`usip_decode.c`. The table is an empirical description, not a vendor
specification: every form carries a confidence level (`high`, `medium`, `low`,
`format-only`) that the `aoj` output reports under `opex.confidence`.

### The packet model

* The unit is the 16-bit big-endian halfword. A **packet** is the run of units up
  to and including the first one with bit 15 set (at most 8 units); packets start
  at 2-byte alignment and the units of a packet execute in parallel.
* An **instruction** is a *head* (bit 15 = 0) plus 0, 1 or 2 *tails*
  (16/32/48 bits). Tails are not necessarily adjacent to their head: a packet is
  a sequence of groups laid out *heads first, then tails round-robin* (`S S O O`
  is two 32-bit instructions interleaved; `x008 X hi lo hi' lo'` a 48-bit call
  interleaved with another 48-bit op). No bit selects the layout. The decoder
  enumerates every group split and head/tail assignment the table allows and
  keeps the reading with the fewest unknown units, then the fewest instructions,
  then the fewest groups, then the documented tie-break penalties; ties keep the
  first enumerated reading (`opex.packet.ambiguous` tells when a tie existed).
* Only **slot 0** (the first unit) can be control flow: `b<cond>`, `b`, `call`,
  `loop`, `ret`, the 16-bit `bz.s`/`bnz.s`/`b.s`/`call.s`, `call.abs`/`b.abs`.
  When the control instruction does not close the packet, the **rest of the
  packet is its delay slot** (both paths execute it). The plugin reports
  `delay` = number of ops that follow in the packet and `fail` = the next packet.
* Hardware loops: `loop rX, last=ADDR` repeats the following instructions up to
  `ADDR` (inclusive) `rX` times; it is reported as a reference (`ptr`), not a
  branch.

### What one `pd` line is

A decode is one **op per run of adjacent units that belong to the same
instruction**: an instruction whose tails are adjacent is one op of 4 or 6 bytes;
an interleaved instruction shows its head as a 2-byte op with the full operands
and its displaced tails as `.unit 0xNNNN (mnemonic @ head)` ops, so that every
address of the stream is covered exactly once and the sizes add up. The decoder
needs the packet context: the decode at a packet start parses the whole packet
and caches it in the session, the following decodes inside the packet (linear
disassembly, function analysis) reuse that reading, and a decode at an address
that is not cached is treated as a packet start — true for branch targets and
function starts, not for an arbitrary mid-packet
address, which may then read differently than in the linear listing.
`R_ARCH_INFO_MAXOP_SIZE` is 16 in this mode so that `ao`/analysis see the whole
packet.

### Mnemonics and operands

Registers `r0-r15` (`r14` = SP, `r15` = LR), the second bank is written `rN!`,
accumulators `A0-A3` (`mfacc rA, Ak.{lo,hi,ext}`), classic CSRs by name
(`mfcr`/`mtcr`), extended CSRs by number (`mfcsr`/`mtcsr`). Immediates carry a
`#`; memory operands are `[rA+off]`, `[rA]+`, `[sp+off]`, `[#addr]`. Branch
targets and `loop` ends are printed absolute. Forms whose operation is unknown
but whose grouping is established are **format-only** and start with `.`
(`.hword`, `.word`, `.w48`, `.dsp`, `.op4imm`, `.hi`/`.lo`/`.ext` ...) or end with
`?` (`ld.w?`, `clr.a?`): they are grouped correctly so that the packet and delay
slot model stays right, and reported with the `unk` type. `.lo`, `.ext`, `.be79`
and the 2-unit `bz.s` come from context rules, not table entries.

### Analysis

Operation types: `cjmp` with `cond` for the compare-and-branch forms (there are
no flags on this core), `jmp`, `call`/`rcall`, `ret`, `load`/`store` with
`refptr`/`ireg`/`disp` (`stackop` on `r14`), `mov` with `val` for the immediate
moves, `add`/`sub`/`and`/`or`/`xor`/`shl`/`shr`/`sar`/`mul`/`div`/`cmp`/`cmov`,
`rpush`/`pop` for `save`/`restore`, `swi` for `sys`. `opex` carries the form id,
confidence, kind, slot, unit addresses, the delay-slot flag and the operands.
The register profile exposes the ABI (`SP=r14`, `LR=r15`, arguments `r0-r7`,
return `r0`). No ESIL is produced for uSIP.

### Limitations

* The reading is table-driven and deterministic. Two kinds of packets can read
  differently from the intended one: `S S O O` packets where several head/tail
  assignments have the same cost (ties, flagged by `opex.packet.ambiguous`), and
  control flow in open packets (`call`/`b`/`loop` followed by delay-slot ops)
  when the branch reading is not the cheapest one. A disassembler that knows the
  function table can prefer the reading whose target is a function start or a
  packet boundary.
* Open points of the ISA: the size of the second register bank, bit 13 (`m`) of
  the 32-bit forms and bit 8 (`x`) outside the validated places, the exact
  `save w` frame size, the sign of the half/byte loads of the 48-bit family,
  `sys #2/#4/#8`, `L_mult` vs `L_mult.e`.
* A decode in the middle of a packet without the packet cached (e.g. `ao` at an
  arbitrary address) sees a different packet than the linear listing.
* At the end of a map, `ao` pads the read with `0xff`, which is a legal closing
  unit; the disassembly path (`pd`) gets the exact bytes and marks the packet
  `truncated`.

See [doc/usip.md](doc/usip.md) for the table format and the constraint and
context-rule semantics.

## Analysis and emulation

The MS15E30 decoder provides operation types, direct targets, register-indirect
jumps/calls, returns, condition codes, delay counts, memory widths and signedness,
operand values, JSON operands, and the register profile. Relative targets wrap
at 32 bits. Delay-slot counts are in decoded instructions/bundles; the
fallthrough address is computed from their actual lengths when lookahead is
available. If lookahead is insufficient, delayed fallthrough remains unknown.

ESIL covers register/immediate moves, ordinary integer arithmetic and logic,
logical/arithmetic shifts, leading-bit counts, scalar min/max, conditional
inversion, multiplication, loads/stores, and immediate control flow,
including signed/unsigned comparisons. It does not model carry/borrow flags,
DSP saturation/rounding, interrupt status restoration, delayed control-flow
execution, hardware-loop execution, or parallel bundle execution. These
instructions still disassemble. Hardware-loop setup reports the loop-end
reference; automatic loop back edges are not inferred.

A packed pair is one four-byte decode unit, displayed as `slot0 | slot1`.
Control flow in its second slot is retained. Other pairs have `unk` as their
aggregate operation type, and operand JSON records their slot numbers. This
preserves decode boundaries without inventing a sequential execution model.
Program and data memory are separate on MD32; r2's usual flat memory view needs
appropriate maps for your firmware before memory emulation is useful.

## Verification

```sh
make test
```

This runs native decoder/parser tests, exhaustive halfword/truncation checks, actual r2
plugin/analysis/ESIL tests, and checks all **1,128 functions / 100,275 instruction
lengths** against the supplied uSIP inventory. The original private `dsp.bin` and
`DbgInfo` files are not required.

Optional independent vendor comparison (see [research notes](doc/research.md)
for downloads and checksums):

```sh
python3 -m venv /tmp/md32-verify
/tmp/md32-verify/bin/pip install unicorn
/tmp/md32-verify/bin/python test/test_oracle.py /tmp/md32-objdump
```

The test emulates the vendor's original x86-64 disassembly function using
Unicorn and compares decoded text, operands, validity, and lengths. Use
`--quick` for a smaller run or `--firmware firmware.be.bin` to add a firmware
image. The checked run included **141,924 cases with zero mismatches**, including
all halfword patterns, randomized operands for every vendor instruction form,
packed pairs, and the MT8173 VPU program image.

See [doc/research.md](doc/research.md) for provenance, the binutils findings,
MD380 distinction, and remaining research questions.

## Firmware exploration and strict ESIL execution

The newer `third_party/v2/r2pkg` bundle adds BRP and a CSV inventory covering
1,301 functions. `tools/analyze_firmware.py` reports the startup probes,
purpose/structure, points of interest, missing encodings, string scan, mapping
conflicts and plugin fixes, and writes the complete listings plus the
three-image loader script into a local `usipdata/` directory. Those artifacts
are derived from the third-party firmware, so the directory is gitignored and
not shipped.

```sh
make test
python3 tools/analyze_firmware.py
r2 -a md32 -c '. usipdata/load-usip.r2' malloc://1

tools/md32-run --cpu usip \
  --image third_party/v2/r2pkg/bin/usip_sec0.bin@0x400e0000 --vector
```

The runner uses separate code/data maps. Add `--data FILE@BASE` for known data,
`--ram BASE:SIZE` for uninitialized RAM, `--zero BASE:SIZE` for deliberately
zeroed RAM, and `--reg NAME=VALUE` for known register state. It reports JSON and
stops on unresolved semantics, unknown memory/register state or unmodeled MMIO.
A reported stop is an analysis result, not a successful firmware boot. The
supplied uSIP reset/startup probes currently complete zero instructions.
