# C-Am-F-G arpeggios, ascending and descending, at 150 BPM (25.6 seconds).
aui 44100 16 1
# 1.6 seconds of 16-bit mono: four quarter notes per buffer.
aub 141120
auN 60
auea

# Frequencies in Hz, rounded to the nearest integer.
f C4=262
f E4=330
f G4=392
f C5=523
f A3=220
f A4=440
f F3=175
f F4=349
f G3=196
f B3=247
f D4=294

# aua takes Hz offsets from the root, rather than semitone intervals.
# Four equal steps: root, third, fifth, octave; then the reverse.
(arp root third fifth octave;aua 0 $1-$0 $2-$0 $3-$0;auws $0;au.;aua $3-$0 $2-$0 $1-$0 0;auws $0;au.)
(progression;.(arp C4 E4 G4 C5);.(arp A3 C4 E4 A4);.(arp F3 A3 C4 F4);.(arp G3 B3 D4 G4))
2.(progression)

aue
