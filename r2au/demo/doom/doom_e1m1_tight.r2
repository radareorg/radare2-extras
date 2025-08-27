# r2au – DOOM E1M1 (At Doom’s Gate) – macro-friendly, note‑accurate riff
# Requires the r2au plugin loaded.

# -------- init --------
aui 44100 16 1
aub 16K
# gentle pluck envelope (attack -> decay)
auN 100 92 78 60 42

# -------- helper macros (learned from your style) --------
# play <freq> for <secs>
(pl; auws $0; au.; sleep $1)
# set instrument/oscillator: s(sine) z(saw) p(pulse) t(triangle) n(noise)
(ins; auw$0)
# short kick/noise hit
(dr; aun white, auws 70, au.;)
# quick arpeggio chord (f0, f1, f2)
(arp; auea; auws $0; au.; auws $1; au.; auws $2; au.; aue)

# -------- note table (Hz) --------
# low bass + lead registers used
f E2=82
f E3=165
f B2=123
f D3=147
f C3=131
f A2=110
f G2=98
f Bb2=117
f E4=330
f F4=349
f G4=392
f A4=440
f Bb4=466
f B4=494
f C5=523
f D5=587
f E5=659
f F5=698
f G5=784

# -------- groove helpers --------
# tight staccato and slightly longer hit
f STAC=0.12
f LONG=0.18
# very short ghost note
f GHO=0.06

# -------- set timbres --------
.(ins z)()        # saw for the lead
# optional: swap to pulse for variation -> .(ins p)()

# -------- main riff (E5–D5–F5–E5–D5–C5–B4–C5–D5) --------
(riff; .(pl E5 STAC); .(pl D5 STAC); .(pl F5 STAC); .(pl E5 STAC); .(pl D5 STAC); .(pl C5 STAC); .(pl B4 STAC); .(pl C5 STAC); .(pl D5 LONG);)

# tail turn-around (D5–C5–B4) -> back to start
(turn; .(pl D5 STAC); .(pl C5 STAC); .(pl B4 LONG);)

# power-chord color hits using arpeggio (E5–B4–E5 etc.)
(color; .(arp E5 B4 E5); sleep 0.05; .(arp D5 A4 D5); sleep 0.05; .(arp F5 C5 F5); sleep 0.05; .(arp E5 B4 E5);)

# simple bass pedal on E with chromatic walk (E–E–E–E | E–E–D–C–B)
(bassbar; .(ins t); .(pl E3 GHO); .(pl E3 GHO); .(pl E3 GHO); .(pl E3 GHO); .(pl E3 GHO); .(pl E3 GHO); .(pl D3 GHO); .(pl C3 GHO); .(pl B2 GHO); .(ins z);)

# tiny kick/noise pattern to give pulse
(drums; .(dr); sleep 0.07; .(dr); sleep 0.14; .(dr); sleep 0.07; .(dr);)

# -------- play structure --------
# Intro: two bars to establish tempo
2.(riff)
.(turn)

# Add color stabs
.(color)

# Main loop: riff + bass pedal underpinning + light drums
# (repeat a few times; tweak counts to taste)
3.(riff); .(bassbar); .(drums)

# Outro: stronger envelope decay and final hit
auN 100 86 64 40 18
.(pl E5 0.25)()
aue
