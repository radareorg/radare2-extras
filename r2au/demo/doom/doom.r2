# At Doom's Gate (DOOM E1M1), Bobby Prince.
# Monophonic guitar arrangement, transcribed from the original D_E1M1 score.
# 44 bars in 4/4 at 110 BPM (96 seconds), including the fills and key changes.
# Durations are in 32nd notes: 6014 bytes / (44100 Hz * 2 bytes) per step.
# Let au. clock playback; sleeping after it would add gaps and slow the riff.
aui 44100 16 1
aue
auN 60 60 55 50 45 40 35 25 10 0
f step=6014

# MIDI note numbers. auf indexes C0 as zero and returns tenths of a Hz.
f E2=40
f A2=45
f Bb2=46
f B2=47
f C3=48
f Cs3=49
f D3=50
f Ds3=51
f E3=52
f F3=53
f Fs3=54
f G3=55
f Gs3=56
f A3=57
f B3=59
f C4=60
f Cs4=61
f D4=62
f Ds4=63
f E4=64
f Fs4=66
f G4=67
f A4=69
f B4=71
f E5=76
f G5=79
f B5=83

# Sine keeps the pitches accurate at this sample rate.
"(note key steps;aub step*$1;auws (`auf $0-12`+5)/10;au.)"

# First half of a bar, followed by either a turnaround or a sustained ending.
(head root high middle;.(note $0 2);.(note $0 2);.(note $1 2);.(note $0 2);.(note $0 2);.(note $2 2);.(note $0 2);.(note $0 2))
(tail root low flat turn last;.(note $1 2);.(note $0 2);.(note $0 2);.(note $2 2);.(note $0 2);.(note $0 2);.(note $3 2);.(note $4 2))
(held root low flat;.(note $1 2);.(note $0 2);.(note $0 2);.(note $2 10))

# E riff: E E E' E E D' E E | C' E E Bb E E B C'.
# The same intervals give the A and C# sections.
(riff root;.(head $0 $0+12 $0+10);.(tail $0 $0+8 $0+6 $0+7 $0+8))
(riff-long root;.(head $0 $0+12 $0+10);.(held $0 $0+8 $0+6))

# Later variation raises the melody to G F# Eb D over the E pedal.
(variation root;.(head $0 $0+15 $0+14);.(tail $0 $0+11 $0+10 $0+10 $0+12))
(variation-long root last;.(head $0 $0+15 $0+14);.(held $0 $0+12 $1))

# Fast fills occupy the second half of a bar (sixteen 32nd notes).
(fill1;.(note Fs4 1);.(note E4 1);.(note Ds4 1);.(note Fs4 1);.(note A4 1);.(note G4 1);.(note Fs4 1);.(note Ds4 1);.(note Fs4 1);.(note G4 1);.(note A4 1);.(note B4 1);.(note A4 1);.(note G4 1);.(note Fs4 1);.(note Ds4 1))
(fill2;.(note B4 1);.(note G4 1);.(note E4 1);.(note G4 1);.(note B4 1);.(note G4 1);.(note B4 1);.(note E5 1);.(note B4 1);.(note G4 1);.(note B4 1);.(note G4 1);.(note B4 1);.(note E5 1);.(note G5 1);.(note B5 1))
(fill3;.(note E4 1);.(note D4 1);.(note C4 1);.(note E4 1);.(note C4 1);.(note A3 1);.(note C4 1);.(note E4 1);.(note A4 1);.(note E4 1);.(note C4 1);.(note E4 1);.(note C4 1);.(note E4 1);.(note C4 1);.(note A3 1))
(fill4;.(note E4 1);.(note G4 1);.(note B3 1);.(note G3 1);.(note E4 1);.(note B3 1);.(note G4 1);.(note E4 1);.(note G4 1);.(note E4 1);.(note B3 1);.(note G3 1);.(note E4 1);.(note G4 1);.(note B4 1);.(note E5 1))
(fill5;.(note Ds4 1);.(note C4 1);.(note B3 1);.(note Fs3 1);.(note Fs4 1);.(note Ds4 1);.(note B3 1);.(note A3 1);.(note A4 1);.(note Fs4 1);.(note Ds4 1);.(note B3 1);.(note B4 1);.(note A4 1);.(note Fs4 1);.(note Ds4 1))
(fill6;.(note E5 1);.(note B4 1);.(note G4 1);.(note E4 1);.(note B4 1);.(note E5 1);.(note B4 1);.(note G4 1);.(note E4 1);.(note G4 1);.(note B4 1);.(note G4 1);.(note E5 1);.(note B4 1);.(note G4 1);.(note E4 1))
(fill7;.(note A4 1);.(note Fs4 1);.(note Ds4 1);.(note B3 1);.(note A3 1);.(note Fs3 1);.(note Ds3 1);.(note B2 1);.(note B4 1);.(note A4 1);.(note Fs4 1);.(note Ds4 1);.(note B3 1);.(note A3 1);.(note Fs3 1);.(note Ds3 1))

# Bars 1-8: opening riff.
.(riff E2)
.(riff-long E2)
.(riff E2)
.(riff-long E2)
.(riff E2)
.(riff-long E2)
.(riff E2)
.(head E2 E3 D3)
.(fill1)

# Bars 9-16: repeat in E, then move to A.
.(riff E2)
.(riff-long E2)
.(riff E2)
.(head E2 E3 D3)
.(fill2)
.(riff A2)
.(riff-long A2)
.(riff A2)
.(head A2 A3 G3)
.(fill3)

# Bars 17-24: E, C#, chromatic B-Bb-A descent, then E.
.(riff E2)
.(riff-long E2)
.(riff E2)
.(riff-long E2)
.(riff Cs3)
.(head B2 B3 A3)
.(note G3 2)
.(note Bb2 2)
.(note A2 2)
.(note F3 10)
.(riff E2)
.(head E2 E3 D3)
.(fill4)

# Bars 25-32: E riff, then the higher variation.
.(riff E2)
.(riff-long E2)
.(riff E2)
.(head E2 E3 D3)
.(fill5)
.(variation E2)
.(variation-long E2 Cs3)
.(variation E2)
.(head E2 G3 Fs3)
.(fill6)

# Bars 33-40: variation in A, then back to E.
.(variation A2)
.(variation-long A2 G3)
.(variation A2)
.(head A2 C4 B3)
.(fill3)
.(variation E2)
.(variation-long E2 Cs3)
.(variation E2)
.(variation-long E2 Cs3)

# Bars 41-44: higher C# and B turnarounds, final E variation and fill.
.(head Cs3 G4 Fs4)
.(tail Cs3 E4 Cs4 Cs4 E4)
.(head B2 Fs4 E4)
.(note Ds4 2)
.(note Bb2 2)
.(note A2 2)
.(note B3 10)
.(variation E2)
.(head E2 G3 Fs3)
.(fill7)
