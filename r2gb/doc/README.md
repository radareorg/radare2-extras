# Game Boy emulation notes

These notes describe the DMG/SM83 implementation in this directory and
lessons from building the related Game Gear emulator.

- [CPU and ESIL](cpu-and-esil.md): flags, instruction clocks, and peripheral hooks.
- [Memory and LCD](memory-and-lcd.md): banked cartridges, aliases, tile rendering, and RGB output.
- [Input, audio, and host pacing](input-audio-and-pacing.md): held buttons, PCM queues, and frame deadlines.

The [Game Gear debugging notes](../../r2gg/doc/README.md) include the
Columns DAA failure and Sonic's PSG sample-playback behavior. They should
not be treated as Game Boy hardware behavior.
