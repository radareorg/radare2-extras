# r2au chiptune – Rhythm/Drums channel
# ---- init ----
aui 44100 16 1
aub 8K

# Drum hits
# kick <dur>
(k; auN 100 90 60 30 12; auws 65; au.; sleep $0)
# snare <dur>
(s; auN 100 95 85 40 10; aun white; au.; sleep $0)
# hihat <dur>
(h; auN 100 80 50 15 5; aun white; au.; sleep $0)

(k; auN 100 90 60 30 12; auws 65; au.; sleep $0)
(s; auN 100 95 85 40 10; aun white; au.; sleep $0)
(h; auN 100 80 50 15 5; aun white; au.; sleep $0)

# One bar (4/4) with eighth-note hats, K on 1 & 3, S on 2 & 4
(bar; .(k 0.25); .(h 0.25); .(s 0.25); .(h 0.25); .(k 0.25); .(h 0.25); .(s 0.25); .(h 0.25))

# Play 16 bars
16.(bar)
