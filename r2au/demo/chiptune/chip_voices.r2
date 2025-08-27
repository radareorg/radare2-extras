# r2au chiptune – Voices/Arpeggio channel (Am–G–F–E)
# ---- init ----
aui 44100 16 1
aub 16K
auN 100 92 78 60 42

# play <freq> <secs>
(pl; auws $0; au.; sleep $1)

# Am arp: A4–C5–E5–C5 (eighths)
(arpA; .(pl 440 0.25); .(pl 523 0.25); .(pl 659 0.25); .(pl 523 0.25))
# G arp: G4–B4–D5–B4
(arpG; .(pl 392 0.25); .(pl 494 0.25); .(pl 587 0.25); .(pl 494 0.25))
# F arp: F4–A4–C5–A4
(arpF; .(pl 349 0.25); .(pl 440 0.25); .(pl 523 0.25); .(pl 440 0.25))
# E arp: E4–G#4–B4–G#4
(arpE; .(pl 330 0.25); .(pl 415 0.25); .(pl 494 0.25); .(pl 415 0.25))

# Two bars per chord
(block; 2.(arpA); 2.(arpG); 2.(arpF); 2.(arpE))

# Loop blocks
8.(block)
