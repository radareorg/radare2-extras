# SM83 execution: similar syntax can hide different hardware

## Game Boy flags are not Z80 flags

The DMG CPU is the SM83. In the profile used by this emulator, F contains
Z at bit 7, N at bit 6, H at bit 5, and C at bit 4; the low nibble is not a
second set of status flags. POP AF must not restore arbitrary low bits.
There is no Z80 parity/overflow flag, IX/IY addressing, or EXX register bank.

That distinction mattered when adding Game Gear support: the pre-existing
Z80 register profile had copied the Game Boy layout. A disassembler can
print plausible instructions while an emulator silently tests the wrong bits.
Architecture selection alone is not evidence that register semantics match.

## A step is not a clock tick

`aes N` counts execution steps. Different instructions take different cycle
counts, and conditional branches can have different taken/not-taken costs.
A halted CPU still needs peripheral clocks so a timer or LCD interrupt can
wake it. `gameboy_step`, `gameboy_before`, and `gameboy_tick` connect those
clocks to ESIL.

The plugin also handles delayed interrupt enabling and HALT behavior. Its
`cmd.esil.step` and `cmd.esil.stepout` hooks are part of the emulated machine.
A raw `ae` expression is useful for testing an instruction's arithmetic, but
it does not by itself advance this entire console model.

## Decimal adjustment is an instruction-level regression target

BCD instructions use arithmetic history through H/N/C, not just the final
accumulator value. Tests need addition, subtraction, half-carry, and decimal
carry boundaries. The Columns bug in the sibling Z80 backend illustrates
another hazard: ESIL relational operators can use a signed register width.
A successful test of `99+1` alone did not validate unchanged BCD digits.

The Game Boy plugin has its own DAA operator in radare2's
`libr/arch/p/gb/plugin.c`. The Z80 fix must not be copied blindly into that
operator: the CPU profiles and available flags differ.

## Keep debugging and fast playback roles visible

Visual playback caches decoded expressions and register descriptors, checking
instruction bytes so changed banks and RAM code are noticed. Normal ESIL
stepping remains the path for analysis hints, pins, and interactive
inspection. Step-back recording cannot reconstruct the whole LCD/APU/mapper
state merely by restoring CPU registers.

Relevant code: [`core_gb.c`](../core_gb.c),
[`registers.inc.c`](../registers.inc.c),
[`instructions.inc.c`](../instructions.inc.c), and
[`tests`](../tests/). More complete hardware background:
[Pan Docs](https://gbdev.io/pandocs/).
