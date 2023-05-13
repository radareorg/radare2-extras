#include <r_core.h>

typedef struct {
	const char *note;
	float freq;
} Tone;

#define TONES 96
Tone tones[TONES] = {
	{ "C0", 16.35 },
	{ "C0$", 17.32 },
	{ "D0", 18.35 },
	{ "D0$", 19.44 },
	{ "E0", 20.60 },
	{ "F0", 21.83 },
	{ "F0$", 23.12 },
	{ "G0", 24.50 },
	{ "G0$", 25.96 },
	{ "A0", 27.50 },
	{ "A0$", 29.14 },
	{ "B0", 30.87 },
	{ "C1", 32.70 },
	{ "C1$", 34.65 },
	{ "D1", 36.71 },
	{ "D1$", 38.89 },
	{ "E1", 41.20 },
	{ "F1", 43.65 },
	{ "F1$", 46.25 },
	{ "G1", 49.00 },
	{ "G1$", 51.90 },
	{ "A1", 55.00 },
	{ "A1$", 58.30 },
	{ "B1", 61.74 },
	{ "C2", 65.41 },
	{ "C2$", 69.30 },
	{ "D2", 73.42 },
	{ "D2$", 77.78 },
	{ "E2", 82.41 },
	{ "F2", 87.31 },
	{ "F2$", 92.50 },
	{ "G2", 98.00 },
	{ "G2$", 103.83 },
	{ "A2", 110.00 },
	{ "A2$", 116.54 },
	{ "B2", 123.47 },
	{ "C3", 130.81 },
	{ "C3$", 138.59 },
	{ "D3", 146.83 },
	{ "D3$", 155.56 },
	{ "E3", 164.81 },
	{ "F3", 174.61 },
	{ "F3$", 185.00 },
	{ "G3", 196.00 },
	{ "G3$", 207.65 },
	{ "A3", 220.00 },
	{ "A3$", 233.08 },
	{ "B3", 246.94 },
	{ "C4", 261.63 },
	{ "C4$", 277.18 },
	{ "D4", 293.66 },
	{ "D4$", 311.13 },
	{ "E4", 329.63 },
	{ "F4", 349.23 },
	{ "F4$", 370.00 },
	{ "G4", 392.00 },
	{ "G4$", 415.30 },
	{ "A4", 440.00 },
	{ "A4$", 466.16 },
	{ "B4", 493.88 },
	{ "C5", 523.25 },
	{ "C5$", 554.37 },
	{ "D5", 587.33 },
	{ "D5$", 622.25 },
	{ "E5", 659.25 },
	{ "F5", 698.46 },
	{ "F5$", 740.00 },
	{ "G5", 783.99 },
	{ "G5$", 830.61 },
	{ "A5", 880.00 },
	{ "A5$", 932.33 },
	{ "B5", 987.77 },
	{ "C6", 1046.50 },
	{ "C6$", 1108.73 },
	{ "D6", 1174.66 },
	{ "D6$", 1244.51 },
	{ "E6", 1318.51 },
	{ "F6", 1396.91 },
	{ "F6$", 1479.98 },
	{ "G6", 1567.98 },
	{ "G6$", 1661.22 },
	{ "A6", 1760.00 },
	{ "A6$", 1864.65 },
	{ "B6", 1975.53 },
	{ "C7", 2093.00 },
	{ "C7$", 2217.46 },
	{ "D7", 2349.32 },
	{ "D7$", 2489.01 },
	{ "E7", 2637.02 },
	{ "F7", 2793.83 },
	{ "F7$", 2959.95 },
	{ "G7", 3135.96 },
	{ "G7$", 3322.44 },
	{ "A7", 3520.00 },
	{ "A7$", 3729.31 },
	{ "B7", 3951.06 }
};

static char tecla(const char *s) {
	return s? (strchr (s, '$')? '|': '_'): '@';
}

float notes_freq(int i) {
	return (i >= 0 && i < TONES) ? tones[i].freq: 0;
}

int notes_index(int i, int black, int from) {
	int j;
	int n = 0;
	int type = black? 0: '$';
	for (j = from; j < TONES; j++) {
		if ((black != -1) && tones[j].note[2] == type) {
			continue;
		}
		if (i == n) {
			return j;
		}
		n++;
	}
	return 0;
}

// #define pf printf
#define pf r_cons_printf

int print_piano(int off, int nth, int pressed) {
	int i, y;
	int och = 0;
	for (y = 0; y <7; y++) {
		char t = 0;
		for (i = off; i < TONES && (i-off < nth); i++) {
			och = t;
			t = tecla (tones[i].note);

			bool isPressed = pressed >= 0 ? (i - off == pressed - 1): false;
			bool isDollar = t != '_';
			if (y == 0) {
				pf (isDollar? ".=": ".==");
			} else if (y == 5) {
				if (isDollar) {
					pf ("-'");
				} else {
					if (off + i==0) {
						pf ("`--");
					} else {
						pf ("---");
					}
				}
			} else if (y == 6) {
				if (t == '_') {
					pf ("%3s", tones[i].note);
				} else {
					pf (" $");
				}
			} else {
				if (t == '_') {
					if (!och || och == '_') {
						pf (isPressed?":##":":  ");
					} else if (och && och == '|' && y < 5) {
						pf (isPressed?"##":"  ");
					} else {
						pf (isPressed?"##":"  ");
					}
				} else {
					if (y == 3) {
						pf ("`-´");
					} else if (y > 3) {
						pf ("   ");
					} else {
						pf (isPressed?"|#|":"| |");
					}
				}
			}
	//		pf ("%s", tones[i].note);
//			pf ("%c", tecla(tones[i].note));
		}
		if (y == 0) {
			pf (".\n");
		} else if (y < 5) {
			pf ("|\n");
		} else if (y == 5) {
			pf ("'\n");
		} else {
			pf ("\n");
		}
	}
	if (pressed >= 0) {
		pf ("Note: %s  Freq: %f\n", tones[off+pressed].note, tones[off+pressed].freq);
	}
	return 0;
}

#if 0
main() {
	print_piano (0, 30, 1);
}
#endif
