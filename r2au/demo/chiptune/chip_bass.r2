# r2au chiptune – Bass channel (Am–G–F–E)
# Run in parallel with chip_lead.r2, chip_rhythm.r2, chip_voices.r2
# ---- init ----
aui 44100 16 1
aub 16K
auN 100 92 78 60 42

# play <freq> <secs>
(pl; auws $0; au.; sleep $1)

# Bars (8 x 1/8 ≈ 0.25s each)
# Am: A2–E3–A3–E3 ×2
(barA; .(pl 110 0.25); .(pl 165 0.25); .(pl 220 0.25); .(pl 165 0.25); .(pl 110 0.25); .(pl 165 0.25); .(pl 220 0.25); .(pl 165 0.25))
# G: G2–D3–G3–D3 ×2
(barG; .(pl 98 0.25); .(pl 147 0.25); .(pl 196 0.25); .(pl 147 0.25); .(pl 98 0.25); .(pl 147 0.25); .(pl 196 0.25); .(pl 147 0.25))
# F: F2–C3–F3–C3 ×2
(barF; .(pl 87 0.25); .(pl 131 0.25); .(pl 175 0.25); .(pl 131 0.25); .(pl 87 0.25); .(pl 131 0.25); .(pl 175 0.25); .(pl 131 0.25))
# E: E2–B2–E3–B2 ×2
(barE; .(pl 82 0.25); .(pl 123 0.25); .(pl 165 0.25); .(pl 123 0.25); .(pl 82 0.25); .(pl 123 0.25); .(pl 165 0.25); .(pl 123 0.25))

(song; .(barA); .(barG); .(barF); .(barE))

# Loop the progression
8.(song)
