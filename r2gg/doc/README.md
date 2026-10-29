# Game Gear debugging notes

These notes distinguish traced failures, implemented fixes, and remaining
uncertainty. ROMs are supplied locally and are not stored in this repository.

- [Columns reset](columns-reset.md): DAA, signed ESIL comparisons, and stack corruption.
- [Sonic sampled voice](sonic-pcm.md): the PSG's period-0/1 DAC behavior.
- [Sonic death investigation](sonic-death.md): lives, collision state, and CPU comparison.
- [Hardware and debugging curiosities](hardware-notes.md): mapping, video, timing, and flag semantics.

- [Columns GG to GB port](gg2gb.md): missing instructions, native lowering, graphics, APU, and build/debug workflow.
