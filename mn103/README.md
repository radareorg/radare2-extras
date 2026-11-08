# MN10300 / AM33 architecture plugin

Native radare2 `RArchPlugin` for the Panasonic (Matsushita) **MN10300** family:
the base MN103 core, the **AM30** extensions, the **AM33** extended registers
and two-operation forms, and the **AM33-2** floating-point unit. The decoder is
driven by the GNU binutils opcode table (`opcodes/m10300-opc.c`, 1129 rows),
with the length rule, the first-match lookup and the operand extraction of
`opcodes/m10300-dis.c` ported to C, so the disassembly agrees with
`objdump -m mn10300` row by row; only the number formatting differs.

The MN10300 is the application CPU of a long line of Panasonic SoCs (DVD and
set-top-box controllers, and the TruePic image processors of the Olympus /
OM System cameras, where it runs the µITRON firmware next to an ARM core).
Linux carried a port of it until 4.16, and GCC and binutils still target it.

## Build and use

Requires radare2 development headers/libraries, `pkg-config`, a C compiler
and make. Tested with radare2 6.2.5 on Linux x86-64 (`make test`).

```sh
make
make install
r2 -a mn103 firmware.bin
```

`make install` copies the architecture and the assembly parse plugins to
`r2 -H R2_USER_PLUGINS`. Override `R2_PLUGIN_PATH` to choose another location;
`make uninstall` removes both. Without installation, load the built libraries
inside r2 with `L /absolute/path/arch_mn103.so` and `L .../asm_mn103.so`, then
`e asm.arch=mn103`.

The plugin is little-endian, byte-aligned (instructions are 1 to 7 bytes long
and functions may start at any address) and uses 32-bit addresses.

### CPU levels

`asm.cpu` selects which rows of the table are accepted, as a superset chain:

| `asm.cpu`      | rows accepted                              |
|----------------|--------------------------------------------|
| `mn10300`      | base MN103 only                            |
| `am30`         | base + AM30 (`mulq`, `mulqu`, `sat16`, ...) |
| `am33`         | base + AM30 + AM33 (`r0`-`r7`, `xr`, pair forms, `mac`, `dmach`, ...) |
| `am33-2` (default) | everything, including the FPU (`fmov`, `fadd`, `fbxx`, ...) |

One deliberate difference from binutils: the `udfNN` / `udfuNN` rows (the
*user-definable* instruction slots) are looked up **after** the named rows that
share their encoding. With `am30` or higher the plugin therefore prints
`mulq d3, d0` where `objdump` without `-M am33` prints `udf00 d3, d0`, and
`swap`, `sat16`, `sat24`, `mcst9`, `mcst48`, `bsch`, `getchx`, `getclx` and
`getx` for the other named slots. With `asm.cpu=mn10300` the placeholders are
kept. The firmware this was written against (OM System / Olympus, AM33) uses
the `mulq`/`mulqu` slots as its 32-bit multiply, which is what the AM30/AM33
names say.

### Syntax

The operand order of the ISA is kept: source first, destination last, as in
binutils. Memory operands are parenthesised; immediates are hexadecimal with a
sign; branch targets are absolute addresses; register lists use the binutils
names.

```
mov 0x10, d3              mov d3, (0x8, a2)        mov (0x1e, sp), d2
movhu (0x8070), d0        mov (d1, a0), d0         fmov (a0+), fs0
call 0x00001457, [d2,d3], 0x2c                     ret [d2,d3], 0x8
add -0x4, sp              cmp 0xce4, d0            blt 0x00001004
mulq d3, d0               div d3, d0               ext d0
movm [a2,a3], (sp)        and 0xf0ff, psw          btst 0x2, (0x8070)
```

With `e asm.pseudo=true` the `mn103` parse plugin rewrites the common forms:
`[a2 + 0x8] = d3`, `d0 = mdr:d0 / d3`, `d3 = (uint16_t) d3`,
`if (<) goto 0x00001004`, `return (restore [d2,d3], frame 0x8)`.

## Analysis

Every row has an analysis type. Control flow: `bra`/`bXX` (with the condition
and sign), the `lXX` loop forms (an unknown conditional jump through `lar`,
set by `setlb`), `jmp` (direct and through `(an)`), `call label,[regs],imm8`,
`calls` (direct and through `(an)`), `ret`/`retf`, `rets`, `rti`, `rtm`, `trap`,
`syscall`, `break`, and the FPU conditional branches. Loads and stores carry
the access size, the base/index register and the displacement or the absolute
address (`ptr`), and stack-relative moves are stack reads/writes.

The stack delta is tracked for `add/sub imm,sp`, `movm` (push/pop), `call`
(return address + the register list + the `imm8` frame), `calls`, `ret`/`retf`
and `rets`. The register profile exposes `sp` as an alias of `a3` at the same
offset, the PSW flags as `zf`/`nf`/`cf`/`vf`, `mdr`/`lir`/`lar`, the AM33
extended registers `r0`-`r7`, `xr1`-`xr15`, `usp`/`ssp`/`msp`/`epsw`, and the
FPU registers (`fd2n` overlapping `fs2n`/`fs2n+1`).

`aoj` reports the operands as `opex` (`form`, `row` in the binutils table, and
each operand as `reg`, `imm`, `target`, `reglist` or `mem` with base, index,
displacement or address, post-increment and size).

## ESIL

ESIL is emitted for the integer core: all `mov`/`movu`/`movbu`/`movhu`/`fmov`
forms (register, immediate, memory with displacement, index, absolute address
and post-increment, the stack and the special registers), `clr`, `add`, `addc`,
`sub`, `subc`, `cmp`, `inc`, `inc4`, `and`, `or`, `xor`, `not`, `asl`, `asl2`,
`asr`, `lsr`, `rol`, `ror`, `ext`, `extb`, `extbu`, `exth`, `exthu`, `mul`,
`mulu` (64-bit result in `mdr:dn`), `mulq`, `mulqu`, `div`, `divu` (`mdr:dn`
dividend, remainder in `mdr`), `btst`, `bset`, `bclr` (register and memory),
`swap`, `swaph`, the branches and loops (`setlb` saves the address of the next
instruction in `lar`), `jmp`, `call`, `calls`, `ret`, `retf` (returns through
`mdr`), `rets`, `rti`, `movm`, `nop`. PSW flags follow the manual for the
arithmetic, compare, logic and shift forms (Z/N; C/V for add, sub and compare).

`movm` and `call`/`ret` model the register-list frame: the `d2`/`d3`/`a2`/`a3`
group at the lowest addresses, then `exother` (`mdrq`, `mcrh`, `mcrl`, `mcvf`),
`exreg0` (`r0`, `r1`), `exreg1` (`r2`-`r7`) and `other` (`d0`, `d1`, `a0`,
`a1`, `mdr`, `lir`, `lar` and the dummy word) above it, as in the `pt_regs`
layout of the Linux port. A pushed `a3` keeps its value from before the
instruction; a popped `a3` is overridden by the final stack-pointer adjustment.

Not modelled: the AM33 three-operand and two-operation forms beyond a plain
`rd = rn OP rm` for the first operation, `mac`/`dmach`/`dmulh` and the other
DSP forms, `sat16`/`sat24`/`bsch`/`mcst*`/`getx`/`putx`, and the floating-point
arithmetic (`fmov` only). Those instructions are decoded and typed but carry
no ESIL.

## Verification

* `test/test_mn103.c` checks the decoder, the analysis fields, the ESIL strings
  and the length rule of every table row against the first-byte rule of
  binutils.
* `test/test_plugin.py` runs the built plugins inside r2: disassembly, pseudo
  syntax, CPU levels, `aoj` metadata, function analysis, and ESIL emulation of
  multiply/divide, flags and branches, `call`/`ret` and `movm` stack frames,
  memory bit operations and a `setlb`/`lne` loop.
* `tools/mn103-dis` is a linear sweep over a raw file in the binutils length
  rule (one line per instruction: offset, size, table row, mnemonic, text), the
  tool used to compare the plugin with a reference decoder.

Against a Python port of `m10300-dis.c` run over 2 M instructions of three
Olympus / OM System camera firmwares (E-PL5, E-M5 Mark III, OM-1 Mark II:
AM33, µITRON), the plugin agrees on every instruction's mnemonic and length
except the `udf` slots that it names (`mulq`, `mulqu`, `getx`, `bsch`) and the
truncated tail of each file. See `doc/mn103.md` for the encoding model and the
decisions behind the analysis.

## Regenerating the table

`mn103_opcodes.h` is generated from the vendored `isa/m10300-opc.c`
(binutils 2.42; the table has not changed since 2.17):

```sh
make mn103_opcodes.h
```

## License

GPL-3.0-or-later: the opcode table is the GNU binutils table and the decoder
follows its disassembler.
