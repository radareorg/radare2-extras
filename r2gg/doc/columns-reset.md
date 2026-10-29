# Columns: a decimal-adjust bug that eventually rebooted the ROM

## Reproduction

The test ROM is the user's `/tmp/columns.gg`, a 32 KiB cartridge. A native
instruction trace reproduced a return to address `0000` at frame 3446,
after 205,885,361 CPU clocks. There was no ESIL trap. The apparent reboot
was ordinary CPU control flow through a corrupted return address.

The original short test stopped at frame 939. Displaying the title and the
first gameplay screen did not exercise the later failure. The optional
`make test-rom-long ROM=/tmp/columns.gg` now checks 5,000 additional frames
at the title/attract screen and 5,000 additional gameplay frames.

## Causal chain

The timer routine at `2753` checks whether it should update a BCD counter.
Its increment loop begins at `2767`: load a byte through HL, increment A,
execute DAA, store A, and compare against `60`. A value below `60` ends the
carry chain. Otherwise the routine clears that byte, increments HL, and
continues into the next counter digit.

With A=`01` and no arithmetic flags set, DAA must leave A=`01`. The broken
expression produced A=`61` and set carry. The timer therefore propagated
carries into unrelated memory. The failing trace eventually reached
HL=`de53` with SP=`de4e`; the routine had walked from its counter into the
stack. Its final RET loaded zero from an overwritten return address.

## Why the expression failed

ESIL's `>` operation chooses a signed comparison width from its operands.
The expression `0x99,a,>` selected the eight-bit width of A. At that width,
`0x99` is negative, so a small positive accumulator value incorrectly
satisfied the high-digit correction test.

The fix compares the saved accumulator in the 64-bit temporary `t0`:
`0x99,t0,>`. Both byte values are positive at that width. The expression
still uses the original carry, half-carry, and subtract flags to decide the
BCD correction.

This was not a cartridge reset request, a timing workaround, or an
anti-emulation check. A valid Z80 instruction was implemented incorrectly.

## Verification

- `radare2/test/db/esil/z80` covers unchanged BCD values `01` and `80`,
  the actual `INC A; DAA; CP 60` sequence, and carry across `99`.
- `tests/test_core_gg.c` checks all 100×100 valid decimal operand pairs,
  both addition and subtraction, with and without carry/borrow: 40,000
  decimal-adjust cases.
- The long ROM test rejects a return to the cartridge reset entry after
  startup. The previously failing attract sequence reaches frame 5500;
  the gameplay sequence reaches frame 5759 without rebooting.

Addresses and frame numbers describe this ROM and this peripheral model;
other revisions need their own trace. The CPU expression lives in `libr/arch/p/z80/esil.inc.c` in the sibling
radare2 checkout; local tests are in [`tests`](../tests/).

Tested ROM SHA-256: `d57014795c01ad9f051ee7b470a9993f7b0e3a2772f128bb79afa66bcfc1879e`.
