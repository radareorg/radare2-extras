--------------------

Extra documentation


AOC
===

AOC = Audio Oscilator CPU

Assembler
=========

Registers:
----------

r0-31 - 32 general purpose registers

Encoding
--------

[1 byte][arg][arg][arg]
 opcode

arg is 4 bytes 

Instructions
------------
	
li r10, 0x1000   ; r0 = 0x1000 where the
                 ; new wave will be generated
li r1, 0x100         ; size of sample
wav r0, r1, r1              ; syscall ?
fil r0, r1, FILTER_DEC, 20  ; apply filter

add r11, r10, 0x1000
wav r11, 2, 0x1000

li r2, 32 ; repeat
play r10, r1, r2
play r11, r1, r2
wait r0




---


---


`@mikelloc` contributions begin below, feel free to re-arrange or just throw them to fire (exclamation mark).

# Architecture

We try to recreate a virtual architecture capable of SID-like features, so, begin defining some stuff as a base for our ISA.

## Features of the "hardware"

- 3 tone oscillators 
    - 0-4095 Hz for SID emulation
    - 0-16383 Hz for virtual implementation
- 5 waveform types per oscillator
    - sinusoidal (not present in SID)
    - triangle
    - sawtooth
    - pulse with variable duty
    - random noise
- 3 Amplitude Modulators
    - range 0-48 dB
- 3 envelope generators
    - exponential response
    - attack rate from 2 ms to 8 seconds
    - decay rate from 6 ms to 24 seconds
- oscillator synchronization (all waves are in sync so we can do some chords or musical theory with them)
- ring modulator
- programable filter (per oscillator will be desirable)
    - low pass
    - band pass
    - high pass
    - q factor adjustable?
- mixer with adjustable volume for each channel/oscillator
- external audio input
- random noise (number/modulation) generator
- 32 one-byte registers

## ISA

Initially we try to do all the design in the 8 bits register mode maybe this result insuficient so we can switch to 16 bits or 32 bit word if needed.

Every instruction will be fixed-sized (oh adored MIPS). A entire instruction will be 4 bytes. One byte for the opcode and 3 bytes for parameters.

Examples of instruction topology:

| byte 1 | byte 2 | byte 3 | byte 4 |
| ------ | ------ | ------ | ------ | 
| opcode | oscil. | value  | value  |
| opcode | addr   | addr   | -      |

## Block diagram

![](https://i.imgur.com/ZeSTinM.jpg)

## Registers


We begin defining 32 one-byte registers, this allows us an easy implementation  (byte-array / enum) and also in the nearly future simplifies the input from .sid where data also are padded as a bytes.

In a more flexible way of implement this we can simply consider each register a memory position

### Oscilator 1

| Reg  | addr  | hex | name                | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0
| ---- | ----- | --- | ------------------- | --- | --- | --- | --- | --- | --- | --- | --- 
| 1    | 00000 | 00  | Frequency Low Byte  | f7 | f6 | f5 |  f4| f3 | f2 |f1  | f0 
| 2    | 00001 | 01  | Frequency High Byte  | f15 | f14 | f13 | f12 | f11 | f10 | f9 | f8 
| 3    | 00010 | 02  | Pulse Width Low Byte  | pw7 | pw6 | pw5 | pw4 | pw3 | pw2 | pw1 | pw0 
| 4    | 00011 | 03  | Pulse Width High Nibble / Volume Nibble  | vol03 | vol02 | vol01 | vol00 | pw11 | pw10 | pw9 | pw1 
| 5    | 00100 | 04  | modes | noise | pulse | sawtooth | triangle | sinus | ring mod. | stop | mute  
| 6    | 00101 | 05  | attack/decay | atck3 | atck2 | atck1 | atck0 | dec3 | dec2 | dec1 | dec0
| 7    | 00110 | 06  | sustain/release| sust3 | sust2 | sust1 | sust0 | rel3 | rel2 | rel1 | rel0

### Oscilator 2

| Reg Núm. | addr | hex | name | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0
| ---- | ---- | --- | ---- | --- | --- | --- | --- | --- | --- | --- | --- 
| 8     | 00000 | 00    | Frequency Low Byte  | f7 | f6 | f5 |  f4| f3 | f2 |f1  | f0 
| 9     | 00001 | 01    | Frequency High Byte  | f15 | f14 | f13 | f12 | f11 | f10 | f9 | f8 
| 10     | 00010 | 02    | Pulse Width Low Byte  | pw7 | pw6 | pw5 | pw4 | pw3 | pw2 | pw1 | pw0 
| 11     | 00011 | 03    | Pulse Width High Nibble / Volume Nibble  | vol03 | vol02 | vol01 | vol00 | pw11 | pw10 | pw9 | pw1 
| 12     | 00100 | 04    | modes | noise | pulse | sawtooth | triangle | sinus | ring mod. | stop | mute  
| 13 | 00101 | 05 | attack/decay | atck3 | atck2 | atck1 | atck0 | dec3 | dec2 | dec1 | dec0
| 14 | 00110 | 06 | sustain/release| sust3 | sust2 | sust1 | sust0 | rel3 | rel2 | rel1 | rel0

### Oscilator 3

| Reg |  Núm. | addr | hex | name | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0
| ----| ----- | ---- | ---- | --- | --- | --- | --- | --- | --- | --- | --- 
| 15  | 00000 | 00   | Frequency Low Byte  | f7 | f6 | f5 |  f4| f3 | f2 |f1  | f0 
| 16  | 00001 | 01   | Frequency High Byte  | f15 | f14 | f13 | f12 | f11 | f10 | f9 | f8 
| 17  | 00010 | 02   | Pulse Width Low Byte  | pw7 | pw6 | pw5 | pw4 | pw3 | pw2 | pw1 | pw0 
| 18  | 00011 | 03   | Pulse Width High Nibble / Volume Nibble  | vol03 | vol02 | vol01 | vol00 | pw11 | pw10 | pw9 | pw1 
| 19  | 00100 | 04   | modes | noise | pulse | sawtooth | triangle | sinus | ring mod. | stop | mute  
| 20  | 00101 | 05   | attack/decay | atck3 | atck2 | atck1 | atck0 | dec3 | dec2 | dec1 | dec0
| 21  | 00110 | 06   | sustain/release| sust3 | sust2 | sust1 | sust0 | rel3 | rel2 | rel1 | rel0

### Filter

| Reg Núm. | addr | hex | name | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0
| ---- | ---- | --- | ---- | --- | --- | --- | --- | --- | --- | --- | --- 
| 22  | - | - | cut frequency low byte | fc7  | fc6 | fc5 | fc4 | fc3 | fc2 | fc1 | fc0
| 23  | - | - | cut frequency high byte | fc15  | fc14 | fc13 | fc12 | fc11 | fc10 | fc9 | fc8
| 24 | - | - | reserved | - | - | - | - | - | - | - | - |
| 25 | - | - | mode/vol | off | HP | BP | LP | vol03 | vol02 | vol01 | vol00 

### Misc

| Reg Núm. | addr | hex | name | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0
| ---- | ---- | --- | ---- | --- | --- | --- | --- | --- | --- | --- | --- 
| 26 | - | - | tempo  | bpm7 | bpm6 | bpm5 | bpm4 | bpm3 | bpm2 | bpm1 | bpm0
| 27  | - | - | measure | mt3 | mt2 | mt1 | mt0 | mb3 | mb2 | mb1 | mb0
| 28 | - | - | reserved | - | - | - | - | - | - | - | - |
| 29 | - | - | master vol/ext. vol | mv3 | mv2 | mv1 | mv0 | ev3 | ev2 | ev1 | ev0
| 30 | - | - | measure low byte | - | - | - | - | - | - | - | - |
| 31 | - | - | measure high byte / note | - | - | - | - | - | - | - | - |
| 32 | - | - | general purpose | d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0 |

# Run-Time emulation

The emulation may be have two modes, first real-time mode. In the real-time mode the emulator can be used as a real SID so modifying the registers can have and immediate effect in the audio output. We can implement this as we can do in hardware version having an operational unit producing sound and a separate unit for control.

The second operation way will work as a classic sequencer.

Sequencer mode can run from

From 0 to 4096 measures.
From 0 to 16 notes per measure.

Registers 30 and 31 act as a instruction pointer like inside the current song.

# Proposed instructions

Here are a initial convention of instructions. Despite the design of the architecture nearly every operation can be done using only load and store but for more conventional way (sugar syntax) several instruction that allows us to do entire musical creations out from assembler code.

Of course also we need some instructions to garant the turin completeness like: jmp, add, cmp...

## `ld` load

Load parameters from register/memory to a auxiliary register

## `st` store

Sets or alters a value or parameter from the configuration of the CPU

## `pm` play mode

Sets the play mode: real-lime or sequencer. In case of sequencer mode admits a second parameter of an memory address to being played

## `play`/`pl` play

## `stop`/`sp` stop

## `skip`/`sk` skip

Most significant bit is sign bit to indicate a jump forward or backwards. The least 7 bits marks a jump of up to 128 measures.

## `lr` let ring

let ring acts as a "nop" in a musical context, maintains the current configuration of the

## `jmp` jump

## `oscf` set oscillator frequency

First parameter indicates the oscillator (1,2,3), the second the value

## `oscv` set oscillator volume

First parameter indicates the oscillator (1,2,3), the second the value

## `oscm` set oscillator modes

First parameter indicates the oscillator (1,2,3), the second parameter, a byte,  corresponds to the five register of each oscillator

## `mixv` set volume for a mixer channel

Channels 1 to 3 refers to oscillators. Channel 4 is the filter, channel 5 is the external source and channel 6 is the master output.
