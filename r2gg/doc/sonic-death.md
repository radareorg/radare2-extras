# Sonic's immediate death: a false time limit, not an anti-emulation check

## Reproduction and controlled comparison

The user's `/tmp/sonic.gg` is a 256 KiB Sonic 1 Game Gear cartridge, with
header product code 002408 and export region. The reported symptom was
Sonic dying immediately after gameplay starts and reaching GAME OVER.

The first scripted run, made after correcting DAA for Columns, did not
reproduce it: Start was pressed at frame 500 for three frames, released,
and the machine ran another 1,500 frames without movement. At frame 2003
Sonic had three lives and the death flag was clear.

To test whether the earlier fix had already removed the cause, a temporary
diagnostic restored only the old DAA comparison in cached expressions.
With the same ROM and input schedule, frame 2003 instead had zero lives
and the death flag set. This is the controlled before/after reproduction.
The old-expression run enters the timeout death path at frames 1081, 1452,
and 1824, consuming lives 3, 2, and 1 in succession. The fixed-ROM regression
is `make test-sonic ROM=/tmp/sonic.gg`.

## What the game was actually checking

The level clock uses RAM bytes `d2cf–d2d1`: BCD minutes, BCD seconds, and a
subsecond frame counter. The update routine increments the frame counter,
rolls it at 60, and propagates carry into seconds and then minutes through
ADC and DAA. It compares seconds against `60` and minutes against `10`.
The DAA instructions are at `33f2` and `33fe`; the minutes threshold
comparison at `33ff` calls the ordinary death routine at `2ff4`.

The broken unsigned test in DAA turned small valid values into values with
an extra `60`. Seconds therefore overflowed spuriously, then minutes passed
the game's time-limit comparison. The game executed its normal timeout
death path repeatedly until lives were exhausted. The stored clock can still
read `00:00` at death entry: the bad adjusted accumulator is compared before
that minute value is written back to RAM. It did not need to
execute an illegal instruction or detect the emulator.

The root fix is the same wide temporary comparison described in
[the Columns reset note](columns-reset.md). Patching the death routine,
forcing infinite lives, or suppressing interrupts would hide the symptom
while leaving the arithmetic defect in place.

## Useful state for future debugging

| Location | Meaning in this ROM |
| --- | --- |
| `d240` | Lives counter, initialized to 3 |
| `d205` bit 0 | Death-state flag |
| `d2a9` | Ring count |
| `d2cf–d2d1` | Level clock |
| `d3ff` / `d402` | Player X/Y words |
| `2ff4` | Death entry, also used by genuine hazards |

A separate held-right/jump trace reached a normal pit death at frame 2943,
X=3114, Y=400, rings=0; lives changed from 3 to 2 at frame 3032. This is a
useful contrast to the no-movement time-limit reproduction. Any appearance
of the death routine alone is insufficient to diagnose an emulator bug.

The [Game Gear disassembly](https://github.com/TheRavenfreak/Sonic-1-Game-Gear-Disassembly)
helped identify state fields and the timeout path. Some labels in that
disassembly differ by a few bytes from this dump: its death label says
`2ff2`, while the actual call target here is `2ff4`. Runtime register and RAM
traces, plus reinstating the faulty expression, established the actual cause.
Addresses describe this ROM revision and should be verified for other dumps.

## Other instruction defects found during the investigation

Comparing executed instructions with an independent Z80 core exposed CPL
and CCF half-carry masking errors. Both were fixed and have separate CPU
regressions. After those corrections, a temporary comparison reached frame
5503 through startup, movement, and jumping without a documented-register
or memory-write mismatch. It excluded undocumented flag differences and
block-IO flag details; it was not a comprehensive hardware certification.

Those additional fixes are described in [the hardware notes](hardware-notes.md).
They are not needed to explain the controlled DAA/time-limit failure.

Tested ROM SHA-256: `dd605c17c8d24b2db9928beff6d8294fd84184b31c2fa92760ae691db84fd569`.
