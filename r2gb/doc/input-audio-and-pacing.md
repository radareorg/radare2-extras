# Controls, sound queues, and frame deadlines

## Button state needs press and release

The emulator keeps a held-button bitmask. A game samples that state while
it executes; setting a bit and clearing it without running instructions
in between is not a useful press. The hardware joypad register is active-low
and obeys its row-selection bits rather than exposing the mask directly.

Supporting terminals provide key release events through the Kitty keyboard
protocol. The input parser can then hold multiple buttons independently.
On terminals without releases, each press/repeat extends a real-time hold
(default 500 ms). This is a fallback, not an exact physical key state.
Losing terminal focus clears held inputs when the focus-out event is received.

## Audio generation and playback are separate

The APU advances with emulated CPU clocks, even when no output device is
open. It writes 44.1 kHz, signed 16-bit little-endian stereo PCM to the mapped
`gb.audio` ring. The status write offset is the next position, not the start
of the most recent sound. Once the ring wraps, chronological data begins
at that offset and continues across the end of the allocation.

r2au's `auq` command queues PCM for a worker thread. Blocking the emulation
loop until a sound finishes would also stop keyboard polling and LCD
execution. Playback therefore uses small asynchronous submissions and retains
a buffering lead. Audio buffering can absorb short host stalls; it cannot
repair wrong APU register behavior or incorrect CPU instruction semantics.

## Host waiting must not add console time

The DMG model uses 4,194,304 CPU clocks per second and 70,224 clocks per
frame. Play mode computes the frame budget from a monotonic host clock,
executes that budget, and waits until the next frame deadline.

`e gb.usleep=16000` sets the maximum host sleep in microseconds. The actual
sleep is capped at the frame deadline. A value of zero keeps the same
emulated speed but busy-waits when ahead. Large values do not intentionally
slow the console. Manual `aes` execution remains unpaced.

A synthetic playback check measured about 99% CPU with busy-waiting and
33% with the default frame wait, while advancing the same amount of
emulated time. This is a local workload measurement, not a fixed CPU-use
promise for every ROM or terminal.

See [`input.inc.c`](../input.inc.c), [`apu.inc.c`](../apu.inc.c), and the
PTY tests in [`test-gameboy-visual.py`](../tests/test-gameboy-visual.py).
