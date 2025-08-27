# r2au DOOM (millorat) – riff + baix + "bombo" amb soroll
# Requereix el plugin r2au carregat.
#
# Idea: fer servir diferents formes d'ona (saw/pulse/triangle) i l'efecte d'arpegi per
# donar gruix, més una pista simple de percussió amb soroll blanc.
#
# Controls bàsics:
#   aui [rate bits channels]  -> inicialitza el dispositiu àudio
#   aub <bytes>               -> mida del bloc d'àudio (buffer)
#   auwX <freq>               -> omple el bloc amb una ona de tipus X (s,c,z,Z,p,v,n,k,t)
#   au.                       -> reprodueix el bloc actual
#   auN a b c d e             -> envolvent/guany (5 mostres de volum per colpejar dinàmica)
#   auea / auep / aue         -> efectes: arpegi, percent, cap
#   aum <len> <off> @ dst     -> barreja (mix) àudio (no l'usem aquí per simplicitat)
#
# --------------------
# Inicialització
# --------------------
aui 44100 16 1
aub 16K

# Envolvent suau per a notes (atac curt, caiguda)
auN 100 90 75 55 35

# Macros d'ajuda
# "pl"  -> toca una freqüència ($0) amb sleep ($1) segons
(pl;auws $0; au.; sleep $1)

# "ins" -> canvia la forma d'ona per a la pista principal
#   exemples: s (sin), z (saw), p (pulse), t (triangle)
(ins;auw$0)

# "dr"  -> cop de "bombo" amb soroll blanc curt
(dr;aun white, auws 80, au.;)

# "arp" -> acord/arpegi sobre una fonamental ($0) i intervals ($1,$2)
#         usa l'efecte d'arpegi per simular power-chord ràpid
(arp;auea; auws $0; au.; auws $1; au.; auws $2; au.; aue)

# --------------------
# Taula de freqüències utilitzades (Hz)
# --------------------
# E4=330, G4=392, A4=440, Bb4=466, B4=494, C5=523, D5=587, E5=659, F5=698
f E4=330
f G4=392
f A4=440
f As4=466
f B4=494
f C5=523
f D5=587
f E5=659
f F5=698

# --------------------
# Pistes
# --------------------

# Baix (triangle suau), acompanya la fonamental E
.(ins t)()
4.(pl E4 0.10); 2.(pl B4 0.10); 2.(pl E4 0.10);
4.(pl E4 0.10); 2.(pl B4 0.10); 2.(pl E4 0.10);

# Bombo (simplicitat: intercalem cops)
.(dr); sleep 0.05; .(dr); sleep 0.10; .(dr); sleep 0.05; .(dr); sleep 0.10

# Riff principal (saw per donar agressivitat)
.(ins z)()
.(pl E5 0.08); .(pl D5 0.08); .(pl F5 0.08); .(pl E5 0.08); .(pl D5 0.08); .(pl C5 0.08)
.(pl B4 0.10); sleep 0.02; .(pl C5 0.08); .(pl D5 0.08)

# Variació amb acord tipus power-chord via arpegi (E5-B4-E5)
.(ins p)()         # pulse per canviar el color
.(arp E5 B4 E5); sleep 0.06; .(arp D5 A4 D5); sleep 0.06
.(arp F5 C5 F5); sleep 0.06; .(arp E5 B4 E5)

# Repetició curta
2.(pl E5 0.08); .(pl D5 0.08); .(pl F5 0.08); .(pl E5 0.08)

# Final curt amb decay
auN 90 70 55 30 10
.(pl E5 0.20)()

# Reset efectes
aue
