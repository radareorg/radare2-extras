# Sonic: the sampled SEGA voice is volume-driven PSG audio

## The symptom and trace

The opening voice in the user's 256 KiB `/tmp/sonic.gg` sounded like a
buzzing, broken waveform. The ROM was making valid PSG writes. A trace of
the sample player around CPU addresses `7c16–7d02` showed tone periods
`1,0,0`, followed by rapid attenuation writes to channels 0 and 2.

One early pair was `96` followed by `d6`: attenuation 6 on both channels.
The routine then changes those volume nibbles as it reads sample data.
These are not normal musical notes or a separate WAV device.

## The missing hardware behavior

Sega's integrated PSG exposes a constant positive output for tone periods
0 and 1. Rapid volume changes turn that constant level into a crude DAC.
The attenuations are logarithmic, so this is not linear 16-bit source audio.
The [sample-playback research](https://www.smspower.org/Development/SamplePlayback)
and [PSG measurements](https://www.smspower.org/Development/SN76489)
describe this use of the chip.

The emulator previously flipped period 1 as a very fast square wave and
interpreted period 0 as a long-period oscillator. Sampling those signals at
44.1 kHz introduced spurious polarity changes and buzzing into the voice.
Adding queue buffering could not correct a waveform already generated
incorrectly.

The mixer now forces a positive level on tone channels whose period is 0
or 1. Their attenuation and stereo routing still apply. Normal tone periods
and the noise channel retain their oscillator behavior.

## Verification and limits

`test_psg_sample_mode` checks hundreds of output samples at both periods:
attenuation 6 must produce a constant 1029 on the selected left channel,
with a silent right channel. It also checks a volume transition to 1295
and the silence attenuation. This catches the former alternating waveform
without relying on subjective listening.

The ROM still uses the original low-resolution, nonlinear sample stream.
The model does not promise hardware-identical analog filtering or
reconstruction. That remaining accuracy question is distinct from the
period-0/1 oscillator error fixed here.

See [`core_gg.c`](../core_gg.c), `gamegear_sound_write` and `gamegear_tick`,
and [`test_core_gg.c`](../tests/test_core_gg.c).

Tested ROM SHA-256: `dd605c17c8d24b2db9928beff6d8294fd84184b31c2fa92760ae691db84fd569`.
