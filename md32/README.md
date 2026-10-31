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
make. Tested with radare2 6.2.5 on macOS arm64 and on Linux x86-64 (`make test`),
and 6.2.2 on Linux x86-64 (against 6.2.2 the optional `tools/md32-run` runner does not build because
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
table `isa/usip_isa.json` (634 forms, generated into `usip_opcodes.h` by
`tools/gen_usip_tables.py`) and by the packet model implemented in
`usip_decode.c`. The table is an empirical description, not a vendor
specification: every form carries a confidence level (`high`, `medium`, `low`,
`format-only`) that the `aoj` output reports under `opex.confidence`.

### The packet model

* The unit is the 16-bit big-endian halfword. A **packet** is the run of units up
  to and including the first one with bit 15 set (at most 8 units); packets start
  at 2-byte alignment and the units of a packet execute in parallel.
* An **instruction** is a *head* (bit 15 = 0) plus 0, 1 or 2 *tails*
  (16/32/48 bits; the 64-bit `b<cond>.l` prefix forms have three). Tails are not
  necessarily adjacent to their head: a packet is a sequence of groups laid out
  *heads first, then tails round-robin* (`S S O O` is two 32-bit instructions
  interleaved; `x008 X hi lo hi' lo'` a 48-bit call interleaved with another
  48-bit op). No bit selects the layout. The decoder enumerates every group split
  and head/tail assignment the table allows, adds the explicit candidates of the
  packet grammar (the 3-unit `[head][op16][F' = 0 tail]`, the 4-unit `H H T T`
  pair of loads/stores) and keeps the smallest reading in the **prior-free total
  order** `(s0, I, Fv, -A, K)`: unknown units plus the documented tie-break
  penalties, then the number of instructions, then the heads whose tail
  adjacency contradicts the F pattern (head F = 0 and next unit bit 14 = 1 means
  an adjacent tail, otherwise a deferred one), then minus the number of adjacent
  tails, then the lexicographic key of the assignment. Readings tied on the first
  four go through the **K-tie cascade**: `dedup` (identical instruction texts),
  `nowaw` (the only reading without a double register write) and `du2` (a
  differential use-definition score over the neighbouring packets); a tie the
  cascade decides is reported as `opex.packet.tiebreak`, one it cannot decide is
  left to the key and reported as `opex.packet.ambiguous`.
* The **prefix forms**: a packet whose first three (four) units are a 48-bit
  (64-bit, with the `1e0d` extension unit) `b<cond>.l rB, #imm9 / rA, target`
  whose target is a packet start of the same function is that instruction plus
  its delay slot (the rest of the packet); a failing guard just means the normal
  layout. The absolute `call.abs`/`b.abs` prefix (`x008 + hi + lo`) is the other
  prefix rule.
* Only **slot 0** (the first unit) can be control flow: `b<cond>`, `b`, `call`,
  `loop rX`/`loop #N`, `ret`, the 16-bit `bz.s`/`bnz.s`/`b.s`/`call.s`,
  `call.abs`/`b.abs`, the `b<cond>.l` prefix forms (the 32-bit `ret`/`ret?`,
  `jr rB` and `call rB` of the `sys` shape may sit anywhere). The tail of a
  branch/call/loop is at +1 or +2; the control tails with F' = 0 (`call`/`b`/
  `b<cond>` with a 16-bit op in between) and `loop #N` with F = 1 and an S = 0
  tail sit exactly at +2. When the control instruction does not close the
  packet, the **rest of the packet is its delay slot** (both paths execute it).
  The plugin reports `delay` = number of ops that follow in the packet and
  `fail` = the next packet.
* Grammar rules of the layout: `5e0d` is never a tail and `5e0d`/`1e0d` never
  take one (they are the structural no-op `nop.ctl`); a unit with bits 12:9 =
  1010 is a `hi` syllable only inside a formed 48-bit instruction, otherwise an
  ordinary head (a lone `.hi`/`.lo` only after a 48-bit-family head in the
  packet); the `st.h` with the F' = 0 tail takes it at +2 or farther (an
  adjacent tail is two 16-bit ops) and in the first slot loses against a `b.s`
  head whose target is a packet start; an op 5 head on SP never takes a negative
  `ld.d`/`st.d` tail; the immediate set-on-compare forms need an adjacent tail;
  an `.op8?` pair of two slot-family units is two `ldslot`/`stslot` ops; an op 0
  head takes `hi + lo` as one of 16 non-canonical 48-bit constants admitted by
  value; the identical-bit cells `mfacc?` (k >= 2) and `add?`/`st.h?` (cell E)
  are selected by the position of the head inside the packet. Once the layout
  is decided, twenty **post-layout renames** relabel the instructions they
  match (`nop.ctl`, the 16-bit `lsl`/`lsl?`/`sext16`/`zext16` variants, `addi
  rA, #32` next to `cop rA`, `ld.w?` of cell A, the r15-based loads, the
  register `bset`/`bext`, `.ldF0?` and the F' = 0 `ld.h?`/`ld.hu?`, `.3eX0?`).
* Some control forms carry a **target guard**: `loop`, `loop #N`, `b<cond>` and
  `beqz.d`/`bnez.d` with the F' = 0 tail, the `b<cond>.d` with the `[0][1][tt]`
  tail at +2 and the `b<cond>.l` prefix forms need a target at a packet start of
  the same function, `call` with the F' = 0 tail and the open-packet `call.s`
  need a function start, far `b` either. A 32-bit pair whose guard fails is data
  (`.word`; the op C compare-and-branch cell leaves a `.dsp` pair); the 16-bit
  `call.s` falls through to the plain reading; a prefix form is simply not
  taken. A relative `call` into the middle of a known function pays a tie-break
  penalty (`callin`) when the embedder can tell. See
  [target guards](#target-guards) for what the plugin can check.
* Hardware loops: `loop rX, last=ADDR` / `loop# #N, last=ADDR` repeat the
  following instructions up to `ADDR` (inclusive) `rX` / `N` times; they are
  reported as a reference (`ptr`), not a branch (`val` = N).

### What one `pd` line is

A decode is one **op per run of adjacent units that belong to the same
instruction**: an instruction whose tails are adjacent is one op of 4, 6 or 8
bytes; an interleaved instruction shows its head as a 2-byte op with the full
operands and its displaced tails as `.unit 0xNNNN (mnemonic @ head)` ops, so that
every address of the stream is covered exactly once and the sizes add up. The
decoder needs the packet context: the decode at a packet start parses the whole
packet and caches it in the session, the following decodes inside the packet
(linear disassembly, function analysis) reuse that reading, and a decode at an
address that is not cached is treated as a packet start — true for branch
targets and function starts, not for an arbitrary mid-packet address, which may
then read differently than in the linear listing. `R_ARCH_INFO_MAXOP_SIZE` is
16 in this mode so that `ao`/analysis see the whole packet.

### Mnemonics and operands

Registers `r0-r15` (`r14` = SP, `r15` = LR); the second bank is written `rN!`
on the operand it applies to (bit `x` = the data/destination register, bit `m` =
the source/base register, also the compared register of the 32-bit branches and
the destination of `movi rA!, #imm5`, `ss & 2` = the first source of the
three-register ALU forms). Accumulators `A0-A3` (`mfacc rA, Ak.{lo,hi,ext}`),
port I/O `ior rB, [rA]`/`iow rB, [rA]` (`rA` holds the port number; there is no
classic CSR bank on this core), extended CSRs by number (`mfcsr rB, #nn`,
`mtcsr #nn, rA`), the system shape by name (`cop rA`, `rti`, `ieon`, `ieoff`,
`idle`, `lpexit?`, `isync?`, `sys #n`; with the F = S = 0 tail the packet stays
open), `nop32`, `addsp #imm` (SP adjust), `lea? rA, [sp+off]`,
`ldslot`/`stslot rB, #k` (stack-slot access, 6-bit slot, base open),
`ld.d`/`st.d rB:rB+1, [rA+off]` (64-bit pairs, signed offset multiple of 4),
`st.w`/`st.h [rB], #imm` (store of an immediate), `mov32 rB, #imm32` /
`add rB, rB, #imm32` (48-bit constants, by formula or by the value table),
`movhi rB, #imm` (20 bits << 12), `movi? rB, #imm20` / `movi? rB, #-32768`, the
set-on-compare family `seq`/`sne`/`sle`/`slt`/`sgt rB, rA, #imm`, `osl rB, rs1,
#1` (funnel shift), `bset`/`bclr?`/`binv?`/`bext? rd!, rs1, #imm5` and the
register forms `bset`/`bext rd, rs1, rB`, the bit-field family
`fxtu`/`fxts`/`fup rB, rs1, #w, #pos` (extract unsigned / signed, insert; `extu`,
`asr16`, `osl` keep their names), `mtacc? Ak, rs1:rB`, `nop.ctl`, `jr rB`.
Immediates carry a `#`; memory operands are `[rA+off]`, `[rA-off]` (the closed
negative bands of the half-word and word offsets; the word offsets have 14 bits:
`[rA+0x1xxx]`), `[rA]+`, `[rA+rB]`, `[sp+off]`, `[r15+off]`, `[#addr]`. Branch
targets and `loop` ends are printed absolute; the 48/64-bit compare-and-branch
forms are `b<cond>.l rB, #imm9, target` / `b<cond>.l rB, rA, target` (`bne beq
ble blt bge bgt bgeu bgtu`, the open cells `ble.l?`, `bneu.l?`, `bequ.l?`,
`bcc48?`), the delayed 32-bit ones `b<cond>.d` (also with the `[0][1][tt]` tail
at +2). Forms whose operation is unknown but whose grouping is established are
**format-only** and start with `.` (`.hword`, `.word`, `.w48`, `.dsp`, `.op4imm`,
`.op4t0`, `.ldF0?`, `.3eX0?`, `.slot?`, `.hi`/`.lo`/`.ext` ...) or end with `?`
(`ld.w?`, `mtacc?`, `fup?`): they are grouped correctly so that the packet and
delay slot model stays right, and reported with the `unk` type. `.hi`, `.lo`,
`.ext`, `.be79`, the 2-unit `bz.s`, the first-slot `ldslot`/`stslot`/`lea?`, the
split `ldslot`/`stslot` halves and the `H H T T` loads/stores come from context
rules, not plain table entries.
A control instruction printed with a trailing `?` (`call?`, `beqz.d?`, `bne.l?`,
`loop#?`, `bne.d?`) is one whose target guard could not be evaluated (see below).

### Target guards

The guarded forms need to know whether the target is a packet start of the
current function or a function start. The plugin derives **packet starts from
the stream**: the packets decoded earlier in the session (backward targets, and
forward targets of a region already decoded, e.g. after `aa` or on a second
`pd`) and a scan of the bytes radare2 hands the decoder past the current packet
(at most 64 bytes of lookahead). A forward target farther away is unknown.
**Function starts are not available** to an arch plugin (radare2 gives it no
typed access to RAnal). When a guard cannot be evaluated the plugin applies a
fallback measured on the sample the table was built from: the forms whose
unverified readings are right in nearly every case are read anyway, printed
with a trailing `?`, confidence `medium` and `opex.target_guard = "unverified"`
(`call` with the F' = 0 tail at +2, `b` with the F' = 0 tail, `b<cond> rA, #imm`
with the F' = 0 tail, `beqz.d`, the `b<cond>.l` prefix forms with a forward
target, `loop #N` with F = S = 1, with F = 0 and the tail adjacent, and with
F = 1 and the S = 0 tail at +2, `loop rX` with F = 1 and the S = 1 F' = 0 tail
at +2, and the `b<cond>.d` cells with the `[0][1][tt]` tail `bne`/`blt`/`bgeu`/
`bgtu`/`bge` with immediate, `beqz.d`/`bnez.d` and `bleu` with registers); the
others are treated as a failed guard (`loop rX` with the other F' = 0 tails,
`loop #N` with F = 0 and the tail at +2, far `b`, `bnez.d` of the F = S = 0
cell, the register `b<cond>` with the F' = 0 tail, the other `b<cond>.d` cells,
the open-packet `call.s`), i.e. `.word`, the plain 16-bit reading or the normal
layout. A validated guard reports `opex.target_guard = "validated"`. The K-tie
cascade sees the packets decoded earlier in the session and the ones inside the
same lookahead (see `doc/usip.md` §7 for what is approximated).

### Analysis

Operation types: `cjmp` with `cond` for the compare-and-branch forms (there are
no flags on this core; `bequ`/`bneu` are the unsigned equality cells of the
48-bit forms), `jmp`, `call`/`rcall`, `ret` (also `rti`), `rjmp` for `jr rB`,
`io` for `ior`/`iow` (`ireg` = the port register), `load`/`store` with
`refptr`/`ireg`/`disp` (`stackop` on `r14`; `refptr` 8 for `ld.d`/`st.d`; the
signed offsets also appear as the `off` operand of `opex`), `mov` with `val` for
the immediate moves (`movi`, `movi?`, `mov32`, `movhi`),
`add`/`sub`/`and`/`or`/`xor`/`shl`/`shr`/`sar`/`mul`/`div`/`cmp`/`cmov`/`cast`
(`osl` is a `shl`, the set-on-compare family `cmp`, `fxtu`/`fxts` `cast`, `fup`
`or`), `lea` for `lea`/`lea?`, `nop` for `nop32`/`nop.ctl`, `rpush`/`pop` for
`save`/`restore`, `trap` for `trap?`, `swi` for the other system ops; `loop #N`
carries the count in `val`. `opex` carries the form id, confidence, kind, slot,
unit addresses, the delay-slot flag, the target-guard status, the packet's
ambiguity / tie-break and the operands.
The register profile exposes the ABI (`SP=r14`, `LR=r15`, arguments `r0-r7`,
return `r0`). No ESIL is produced for uSIP.

### Limitations

* The reading is table-driven, deterministic and prior-free. Four kinds of
  packets can read differently from the intended one: packets where several
  head/tail assignments tie on the first four keys of the layout order and the
  K-tie cascade cannot decide (flagged by `opex.packet.ambiguous`) or decides
  them with a shorter context than a whole-function scan would give (`du2`),
  control flow in open packets (`call`/`b`/`loop`/`b.s` followed by delay-slot
  ops) when the branch reading is not the cheapest one, the guarded forms whose
  target the plugin cannot check (far `b` to another function or beyond the
  lookahead, the open-packet `call.s`, `loop`/`bnez.d` and the `b<cond>.d` cells
  with a forward target beyond the lookahead), and the `call` pairs whose tail
  choice depends on the `callin` tie-break. A disassembler that knows the
  function table can prefer the reading whose target is a function start or a
  packet boundary and answer `callin`; `UsipGuardCtx` in `usip_decode.h` is the
  hook for that knowledge.
* Open points of the ISA: the remaining layout ties, the sign and width of the
  `?` forms (`ld.d?`/`st.d?` with b10, `ld.w?`/`st.w?` in the 0x800-0xeff band,
  `seq?`/`sle?` with large immediates, `mov32?`, `lea?`, `mfacc?`, `add?`/`st.h?`
  of cell E, `bcc48?`, `movi?`, `mtacc?`, `fup?`, `.ldF0?`), the `f12 = 1 / 3
  mod 4` word displacements below 0x800, `.op4t0` (a stolen tail), `.3eX0?`,
  the op 2 16-bit `addi rA, #simm4` (probably a shift), `ld.w` vs `add` in the
  op 0 F = S = 1 cell, the bit 4 of `loop #N`, the exact `save w` frame size,
  `sys #2/#4/#8`, `L_mult` vs `L_mult.e`, why the scheduler inserts `nop.ctl`.
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
