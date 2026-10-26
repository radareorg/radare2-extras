radare2-au
==========

This module for r2 enables the `au` command to initialize the
audio device, create waves, apply filters and interactively
play sounds from the custom visual mode.

Slides: [RidingTheWave.pdf](https://github.com/radareorg/r2con2018/raw/master/talks/riding-the-wave/r2con2018-RidingTheWave.pdf)

--pancake

## Streaming PCM

`auq` queues signed little-endian PCM for a background playback thread. It
leaves the current architecture, seek, and block size unchanged. Samples are
copied from mapped IO; the worker only touches its queue and audio device.

- `auqi [rate bits channels [driver]]`: initialize (default 44100 Hz, 16-bit,
  stereo). Only 16-bit mono/stereo is accepted. The optional libao driver name
  supports `null` for headless tests. `$?` is 1 on success, 0 on failure.
- `auq address length`: enqueue whole sample frames. `$?` is the accepted byte
  count, or 0 when the bounded 32768-byte queue is full or playback failed.
  Retry after it drains; there is no blocking wait for queue space.
- `auqs`: show queued bytes, or -1 on device failure.
- `auq-`: stop playback, discard pending samples, join the thread, and close
  its device. Plugin unload performs the same cleanup.
- `auq?`: help and capability probe (`$? = 1`).

This interface is used by radare2's `r2gb visual` and `r2gb audio` commands.
Use `python3 test-stream.py` after building for silent streaming/lifecycle
checks. Set `R2` to select the radare2 executable.
