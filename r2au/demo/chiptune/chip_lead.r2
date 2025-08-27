# r2au chiptune – Lead/Melody channel
# ---- init ----
aui 44100 16 1
aub 16K
# brighter pluck
auN 100 96 80 58 36

# play <freq> <secs>
(pl; auws $0; au.; sleep $1)

# Helper: short rest
(r; sleep $0)

# Frequencies used (approx, Hz): C5=523 D5=587 E5=659 G5=784 A5=880 B4=494
# Bar templates over Am–G–F–E
(melA; .(pl 659 0.25); .(pl 659 0.25); .(pl 523 0.25); .(pl 587 0.125); .(pl 659 0.125); .(pl 659 0.25); .(pl 523 0.25); .(r 0.25))
(melG; .(pl 587 0.25); .(pl 587 0.25); .(pl 494 0.25); .(pl 587 0.125); .(pl 784 0.125); .(pl 784 0.25); .(pl 587 0.25); .(r 0.25))
(melF; .(pl 523 0.25); .(pl 523 0.25); .(pl 440 0.25); .(pl 523 0.125); .(pl 659 0.125); .(pl 659 0.25); .(pl 523 0.25); .(r 0.25))
(melE; .(pl 494 0.25); .(pl 494 0.25); .(pl 415 0.25); .(pl 494 0.125); .(pl 659 0.125); .(pl 659 0.25); .(pl 494 0.25); .(r 0.25))

(phrase; .(melA); .(melG); .(melF); .(melE))
4.(phrase)
