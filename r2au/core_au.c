/* radare - MIT - Copyright 2018 - pancake */

#if 0
gcc -o core_au.so -fPIC `pkg-config --cflags --libs r_core` core_test.c -shared
mkdir -p ~/.config/radare2/plugins
mv core_au.so ~/.config/radare2/plugins
#endif

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <string.h>
#include "ao.h"
#define _USE_MATH_DEFINES
#include <math.h>
#include "notes.c"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

#define WAVETYPES 12
#define PRINT_MODES 6
// #define WAVECMD "sctkpPn-idzZ"
#define WAVECMD "scktzZpvnsid"

#define WAVERATE 22050
// #define WAVERATE 44100
// SID is 16bit, 8bit sounds too much like PDP
#define WAVEBITS 16

extern void noise_pink(ut8 *buf, int buflen);
extern void noise_brown(ut8 *buf, int buflen);
static int waveType = 0;
static int waveFreq = 500;
static int cycleSize = 220;
static int toneSize = 4096; // 0x1000
static int printMode = 0;
static int auPianoKeys = -1; // XXX not working well yet
static bool zoomMode = false;
static int zoomLevel = 1;
static bool cursorMode = false;
static int cursorPos = 0;
static int animateMode = 0;
static int aBlocksize = 1024*8;
static int keyboard_offset = 0;
static int auEffect = 0;
static short sample;
static ao_device *device = NULL;
static ao_sample_format format = {0};

enum {
	NOISE_WHITE,
	NOISE_PINK,
	NOISE_BROWN,
};


static int *amplitudes = NULL;
static int namplitudes = 0;
static int *chords = NULL;
static int nchords = 0;
static int noiseType = NOISE_WHITE;


#define captureBlocksize() int obs = core->blocksize; r_core_block_size(core, aBlocksize)
#define restoreBlocksize() r_core_block_size (core, obs)

enum {
	SHAPE_SIN,      // .''.''.
	SHAPE_COS,      // '..'..'
	SHAPE_CROSSES,  // ><><><>
	SHAPE_TRIANGLE, // /\/\/\/
	SHAPE_SAW,      // /|/|/|/
	SHAPE_ANTISAW,  // |\|\|\|
	SHAPE_PULSE,    // '_'_'_'
	SHAPE_VPULSE,   // '__'__'
	SHAPE_NOISE,    // \:./|.:
	SHAPE_SILENCE,  // ______
	SHAPE_INC,      // _..--''
	SHAPE_DEC,      // ''--.._
};


enum {
	FILTER_INVERT,    // 1 -> 0
	FILTER_ATTACK,    // ____.'
	FILTER_DECAY,     // -----.
	FILTER_VOLUME,    // _..oo#
	FILTER_INC,       // ++++++
	FILTER_DEC,       // ------
	FILTER_INTERLACE, //  A + B
	FILTER_SHIFT,     // >> >>
	FILTER_ROTATE,    // >>> >>>
	FILTER_MOD,       // %
	FILTER_XOR,       // ^
	FILTER_SIGN,      // + -> -
	FILTER_SCALE,     // *=
};

// aue[type] [arg]
enum {
	EFFECT_NONE,
	EFFECT_ARPEGGIO, // blirping
	EFFECT_PERCENT,
	EFFECT_LAST
};

static void playNote(RCore *core) {
	char waveTypeChar = WAVECMD[waveType % WAVETYPES];
	waveTypeChar = WAVECMD[waveType % WAVETYPES];
	r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
	r_core_cmd0 (core, "au.");
}

void sample_filter(char *buf, int size, int filter, int value) {
	int i, j;
	int isize = size / 2;
	short *ibuf = (short*)buf;
	switch (filter) {
	case FILTER_ATTACK:
		value = isize / 100 * value;
		for (i = 0; i < isize; i++) {
			if (i < value) {
				int total_pending = value;
				int pending = value - i;
				float mul = pending / total_pending;
				ibuf[i] *= mul;
			}
		}
		break;
	case FILTER_DECAY:
		value = isize / 100 * value;
		for (i = 0; i < isize; i++) {
			if (i >= value) {
				float total_pending = isize - value;
				float pending = isize - i;
				float mul = pending / total_pending;
				ibuf[i] *= mul;
			}
		}
		break;
	case FILTER_XOR:
		for (i = 0; i + value< isize; i++) {
			// ibuf[i] ^= value; //ibuf[i + 1];
			ibuf[i] ^= ibuf[i + value];
		}
		break;
	case FILTER_INVERT:
		for (i = 0; i < isize; i++) {
			ibuf[i] = -ibuf[i];
		}
		break;
	case FILTER_DEC:
	case FILTER_INC:
		for (i = 0; i < isize; i++) {
			float pc = (float)i / (float)format.rate * 100;
			if (FILTER_INC == filter) {
				pc = 100 - pc;
			}
			pc /= value;
			pc += 1;
			if (!((int)i % (int)pc)) {
				ibuf[i] = 0xffff / 2;
			} else {
				//	sample = -max_sample;
			}
		}
		break;
	case FILTER_SHIFT:
		value = (isize / 100 * value);
		if (value > 0) {
			const int max = isize - value;
			for (i = 0; i < max; i++) {
				ibuf[i] = ibuf[i + value];
			}
			for (i = max; i < value; i++) {
				ibuf[i] = 0;
			}
		} else {
			/* TODO */
			const int max = isize - value;
			for (i = isize; i > value; i--) {
				ibuf[i] = ibuf[i - value];
			}
			for (i = 0; i < value; i++) {
				ibuf[i] = 0;
			}
		}
		break;
	case FILTER_SIGN:
		if (value > 0) {
			for (i = 0; i < isize; i++) {
				if (ibuf[i] > 0) {
					ibuf[i] = 0;
				}
			}
		} else {
			for (i = 0; i < isize; i++) {
				if (ibuf[i] < 0) {
					ibuf[i] = 0;
				}
			}
		}
		break;
	case FILTER_ROTATE:
		if (value > 0) {
			short *tmp = calloc (sizeof (short), value);
			if (tmp) {
				for (i = 0; i < value; i++) {
					tmp[i] = ibuf[i];
				}
				const int max = isize - value;
				for (i = 0; i < max; i++) {
					ibuf[i] = ibuf[i + value];
				}
				for (i = max; i < value; i++) {
					ibuf[i] = tmp[i - max];
				}
				free(tmp);
			}
		} else {
			/* TODO */
		}
		break;
	case FILTER_INTERLACE:
		if (value < 2) {
			value = 2;
		}
		for (i = 0; i < size / 2; i++) {
			if (!((i / value) % value)) {
				for (j = 0; j< value; j++) {
					ibuf[i] = 0;
				}
			}
		}
		break;
	case FILTER_SCALE:
		if (value < 100) {
			int j = value;
			for (i = 0; i + j < isize; i++) {
				ibuf[i] = ibuf[i + j];
				j++;
			}
			int base;
			for (base = i; i< isize; i++) {
				ibuf[i] = ibuf[i - base];
			}
		} else {
			// TODO
		}
		break;
	case FILTER_MOD:
		for (i = 0; i < isize; i++) {
			ibuf[i] = ibuf[i] / value * value;
		}
		break;
	case FILTER_VOLUME:
		for (i = 0; i < isize; i++) {
			ibuf[i] *= ((float)value / 100);
		}
		break;
	}
}

float arpeggio (float ofreq, int i, int words) {
	int pc = (i * 100) / words;
	if (chords) {
		int block = 100 / nchords;
		int piece = pc / block;
		return ofreq + chords[piece];
	}
	if (pc > 80) {
		return ofreq + 300;
	}
	if (pc > 60) {
		return ofreq + 400;
	}
	if (pc > 40) {
		return ofreq + 200;
	}
	if (pc > 25) {
		return ofreq + 50;
	}
	return ofreq;
}

// affects frequency over time
float au_effect (float ofreq, int i, int words) {
	int pc = (i * 100) / words;
	switch (auEffect) {
	case EFFECT_PERCENT:
		return ofreq * pc / 100; // engine-like sound
	case EFFECT_ARPEGGIO:
		return arpeggio (ofreq, i, words);
	}
	return ofreq;
}

static void au_amplitude (short *words, int count) {
	int i;
	if (!amplitudes) {
		return;
	}
	for (i = 0; i < count;i++) {
		int pc = (i * 100) / count;
		int block = 100 / namplitudes;
		int piece = pc / block;
		float amp = amplitudes[piece];
		float v = (float)(words[i]);
		words[i] = v * (amp / 100);
	}
}

ut8 *sample_new(float freq, int form, int *size) {
	int i;
	short sample; // float ?
	float wax_sample = format.bits == 16 ? 0xffff / 3 : 0xff / 3;
	float max_sample = format.bits == 16 ? 0xffff / 3 : 0xff / 3;
	float volume = 1; // 0.8;
	float pc;
	// int buf_size = format.bits / 8 * format.channels * format.rate;
	int buf_size = 16 / 8 * format.channels * format.rate;
	buf_size = aBlocksize;

	ut8 *buffer = calloc (buf_size, sizeof (char));
	if (!buffer) {
		return NULL;
	}
	if (size) {
		*size = buf_size; // 22050 // huh
	}
	short *word = (short*)(buffer);
	int words = buf_size / sizeof (short);
	float ofreq = freq;
	if (form == SHAPE_NOISE) {
		if (noiseType == NOISE_PINK) {
			noise_pink (buffer, buf_size);
			return buffer;
		}
		if (noiseType == NOISE_BROWN) {
			noise_brown (buffer, buf_size);
			return buffer;
		}
	}
	for (i = 0; i < words; i++) {
		freq = au_effect (ofreq, i, words);
		switch (form) {
		case SHAPE_SILENCE:
			sample = 0;
			break;
		case SHAPE_DEC:
		case SHAPE_INC:
			if (form == SHAPE_INC) {
				float f = freq * (freq * ((float)i / words));
				sample = (short) max_sample * sin (f * (2 * M_PI) * i / format.rate);
			} else {
				float f = freq  - (freq*  ((float)i / words));
				//float f = freq * (100 - pc) / 100;
				sample = (short) max_sample * sin (f * (2 * M_PI) * i / format.rate);
			}
#if 0
			pc = (float)i / (float)format.rate * 100;
			if (form == SHAPE_INC) {
				pc = 100 - pc;
			}
			pc /= freq / 100; // step -- should be parametrizable
			pc += 1;
			if (!((int)i % (int)pc)) {
				sample = max_sample;
			} else {
				sample = -max_sample;
			}
#endif
			break;
		case SHAPE_COS:
			sample = (int)(max_sample * cos (2 * M_PI * freq * ((float)i / format.rate)));
			break;
		case SHAPE_SIN:
			sample = (short) max_sample * sin (freq * (2 * M_PI) * i / format.rate);
			break;
		case SHAPE_SAW:
			{
				int rate = 14000 / freq;
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
				sample = -sample;
				// printf ("%f\n", (float)sample);
			}
			break;
		case SHAPE_ANTISAW:
			{
				int rate = 14000 / freq;
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
				//sample = -sample;
				// printf ("%f\n", (float)sample);
			}
			break;
		case SHAPE_CROSSES:
			{
				if (freq < 1) {
					freq = 1;
				}
				int rate = (11050 / freq);
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
				if (i % 2) {
					sample = -sample;
				}
			}
			break;
		case SHAPE_TRIANGLE:
			{
				if (freq < 1) {
					freq = 1;
				}
				int rate = (11050 / freq);
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
				if (i % 2) {
					sample = -sample;
				}
				if (sample > 0) {
					sample = -sample;
				}
				sample += (32728/3);
				sample *= 2;
			}
			break;
		case SHAPE_PULSE:
			sample = (short) max_sample * sin (freq * (2 * M_PI) * i / format.rate);
			sample = sample > 0? max_sample : -max_sample;
				sample += (sample * ((float)i / words));  // sounds better?
			break;
		case SHAPE_VPULSE:
			sample = (short) max_sample * sin (freq * (2 * M_PI) * i / format.rate);
			sample = sample > 0x5000? -max_sample : max_sample;
			break;
		case SHAPE_NOISE:
			sample = (rand() % (int)(max_sample * 2)) - max_sample;
			sample = (rand() % (int)(32700 * 2)) - 32700;
			int s = (int)sample * (freq / 100);
#if 0
			if (s > 0) {
				s = 32700;
			}
			if (s < 0) {
				s = -32700;
			}
#endif
			sample = s;
			break;
		}
		//sample *= volume;
// printf ("SAMP %d\n", sample);
		/* left channel */
		word[i] = sample;
		// buffer[2 * i] = sample & 0xf;
		// buffer[2 * i + 1] = (sample >> 4) & 0xff;
		// buffer[(2 * i) + 1] = ((unsigned short)sample >> 8) & 0xff;
		// i++;
	}
	au_amplitude (word, words);
	// sample_filter (buffer, buf_size, FILTER_SIGN, 1);
	return buffer;
}

static bool au_init(int rate, int bits, int channels, int endian) {
	ao_initialize ();

	int default_driver = ao_default_driver_id ();
	memset (&format, 0, sizeof (format));
	format.byte_format = endian? AO_FMT_BIG: AO_FMT_LITTLE;
	format.rate = rate;
	format.bits = bits;
	format.channels = channels;
	// format.rate = 11025;

	device = ao_open_live (default_driver, &format, NULL);
	if (!device) {
		eprintf ("core_au: Error opening audio device.\n");
		return false;
	}
	// seems like we need to feed it once to make it work
	if (0) {
		int len = 4096;
		char *silence = calloc (sizeof (short), len);
		ao_play (device, silence, len);
		free (silence);
	}
	return true;
}

static bool au_fini() {
	ao_close (device);
	device = NULL;
	ao_shutdown ();
	return true;
}

static void au_help(RCore *core) {
	eprintf ("Usage: auw[type] [args]\n");
	eprintf (" fill current block with wave\n");
	eprintf (" default wave shape type can be changed like this:\n");
	eprintf (" > 'auws;auw 400' is the same as > 'auws 400'\n");
	eprintf (" args: frequence\n");
	eprintf (" types:\n"
		" (s)in    .''.''.\n"
		" (c)os    '..'..'\n"
		" (z)aw    /|/|/|/\n"
		" (Z)aw    \\|\\|\\|\\\n"
		" (p)ulse  |_|'|_|\n"
		" (v)pulse '__'__'\n"
		" (n)oise  /:./|.:\n"
		" (k)ross..  ><><><>\n"
		" (t)ri..  /\\/\\/\\/\n"
		" (-)silen _______\n"
		" (i)nc    _..--''\n"
		" (d)ec    ''--.._\n"
	);
}

static bool au_mix(RCore *core, const char *args) {
	ut64 narg = *args? r_num_math (core->num, args + 1): 0;
	float arg = narg;
	if (arg == 0) {
		eprintf ("Usage: aum [from] # honors aub blocksize and core->offset\n");
		return true;
	}
	const int bs = aBlocksize; //core->blocksize;
	// eprintf ("[au] Mixing from 0x%"PFMT64x" to 0x%"PFMT64x"\n", narg, core->offset);
	short *dst = calloc (bs, 1);
	short *src = calloc (bs, 1);
	if (!src || !dst) {
		free (src);
		free (dst);
		return false;
	}
	r_io_read_at (core->io, core->offset, (ut8*)dst, bs);
	r_io_read_at (core->io, narg, (ut8*)src, bs);
	int shorts = bs / sizeof (*dst);
	for (int i = 0; i < shorts; i++) {
		st64 sum = src[i] + dst[i];
		dst[i] = sum / 2;
	}
	r_io_write_at (core->io, core->offset, (const ut8*)dst, bs);
	return true;
}

static void auo_help () {
	eprintf ("Usage: auo[r)+-/*_] [value]\n");
	eprintf (" auo) 300   ; echo with 300 bytes of delay\n");
	eprintf (" auo+ 300   ; increment 300 each short (nop)\n");
	eprintf (" auo- 300   ; decrement 300 each short (nop)\n");
	eprintf (" auo* 2     ; increase the volume\n");
	eprintf (" auo/ 2     ; decrease the volume\n");
	eprintf (" auo_       ; audioblock.map(Math.abs)\n");
	eprintf (" auo-       ; audioblock.map(-Math.abs)\n");
	eprintf (" auor 2     ; random value with seed\n");
}

static bool au_anal(RCore *core, const char *args) {
	ut64 narg = *args? r_num_math (core->num, args + 1): 0;
	float arg = narg;
	const int bs = aBlocksize;
	int i, shorts = bs / sizeof (short);
	short *dst = calloc (bs, 1);
	if (!dst) {
		return false;
	}
	r_io_read_at (core->io, core->offset, (ut8*)dst, bs);
	short init = dst[0];
	// XXX not working well
	int direction = (dst[1] > init)? 1: -1;
	bool end = false;
	for (i=2; i<shorts; i++) {
		if (direction > 0) {
			if (dst[i] <= init) {
				if (end) {
					break;
				}
				direction = -1;
				end=true;
			}
		} else {
			if (dst[i] >= init) {
				if (end) {
					break;
				}
				direction = 1;
				end=true;
			}
		}
	}
	if (end) {
		r_cons_printf ("cycle length %d\n", (i*10));
		r_cons_printf ("frequency %d\n", 1000 - (i*10));
	}
	return true;
}

static bool au_operate(RCore *core, const char *args) {
	ut64 narg = *args? r_num_math (core->num, args + 1): 0;
	float arg = narg;
	const int bs = aBlocksize;
	int shorts = bs / sizeof (short);
	short *dst = calloc (bs, 1);
	if (!dst) {
		return false;
	}
	r_io_read_at (core->io, core->offset, (ut8*)dst, bs);
	switch (*args) {
	case ')':
		if (arg >= shorts) {
			eprintf ("Too far.. maxshors is %d not %d\n", shorts, (int)arg);
		}
		for (int i = arg; i < shorts; i++) {
			short val = dst[i - (int)arg] / 4;
			if (val > 0) {
				dst[i] += val;
			} else {
				//dst[i] -= val;
			}
			dst[i] += val;
//eprintf ("%d +%d\n", dst[i], val);
		}
		break;
	case '=':
		for (int i = 0; i< shorts; i++) {
			dst[i] = arg; //src[i];
		}
		break;
	case '_':
		for (int i = 0; i< shorts; i++) {
			dst[i] = R_ABS (dst[i]);
		}
		break;
	case 'r':
		for (int i = 0; i< shorts; i++) {
			dst[i] += (rand() % (int)(arg * 2)) - arg;
		}
		break;
	case '+':
		for (int i = 0; i< shorts; i++) {
			if (dst[i] > 0) {
				dst[i] += arg;
			} else {
				dst[i] -= arg;
			}
		}
		break;
	case '-':
		if (arg) {
			for (int i = 0; i< shorts; i++) {
				if (dst[i] > 0) {
					dst[i] -= arg;
				} else {
					dst[i] += arg;
				}
			}
		} else {
			for (int i = 0; i< shorts; i++) {
				dst[i] = -R_ABS (dst[i]);
			}
		}
		break;
	case '/':
		for (int i = 0; i< shorts; i++) {
			dst[i] /= arg;
		}
		break;
	case '*':
		for (int i = 0; i< shorts; i++) {
			dst[i] *= arg;
		}
		break;
	default:
		auo_help ();
		break;
	}
	r_io_write_at (core->io, core->offset, (const ut8*)dst, bs);
	return true;
}

static char defaultShape = 0;

static bool au_write(RCore *core, const char *args) {
	int size = 0;
	ut8 *sample = NULL;
	ut64 narg = *args? r_num_math (core->num, args + 1): 0;
	float arg = narg;
	if (*args == '?') {
		au_help (core);
		return true;
	}
	if (arg == 0) {
		if (*args) {
			defaultShape = *args;
		} else {
			r_cons_printf ("auw%c\n", defaultShape);
		}
		return true;
	}
	switch (*args) {
	case ' ':
		au_write (core, sdb_fmt ("%c %s", defaultShape, args + 1));
		break;
	case '?':
		au_help (core);
		break;
	case 'k':
		sample = sample_new (arg, SHAPE_CROSSES, &size);
		break;
	case 's':
		sample = sample_new (arg, SHAPE_SIN, &size);
		break;
	case 't':
		sample = sample_new (arg, SHAPE_TRIANGLE, &size);
		break;
	case 'i':
		sample = sample_new (arg, SHAPE_INC, &size);
		break;
	case 'd':
		sample = sample_new (arg, SHAPE_DEC, &size);
		break;
	case 'c':
		sample = sample_new (arg, SHAPE_COS, &size);
		break;
	case 'p':
		sample = sample_new (arg, SHAPE_PULSE, &size);
		break;
	case 'v':
		sample = sample_new (arg, SHAPE_VPULSE, &size);
		break;
	case 'n':
		sample = sample_new (arg, SHAPE_NOISE, &size);
		break;
	case 'z':
		sample = sample_new (arg, SHAPE_SAW, &size);
		break;
	case 'Z':
		sample = sample_new (arg, SHAPE_ANTISAW, &size);
		break;
	case '-':
		sample = sample_new (arg, SHAPE_SILENCE, &size);
		break;
	}
	if (size > 0) {
		int i;
		for (i = 0; i < core->blocksize ; i+= size) {
			int left = R_MIN (size, core->blocksize -i);
			r_io_write_at (core->io, core->offset + i, (const ut8*)sample, left);
		}
	}
	r_core_block_read (core);
	free (sample);
	return true;
}

const char *asciiWaveSin[4] = {
	".''.''.'",
	"''.''.''",
	"'.''.''.",
	".''.''.'",
};

const char *asciiWaveCos[4] = {
	"..'..'..",
	".'..'..'",
	"'..'..'.",
	"..'..'..",
};

const char *asciiWaveTriangle[4] = {
	"/\\/\\/\\/\\",
	"\\/\\/\\/\\/",
	"/\\/\\/\\/\\",
	"\\/\\/\\/\\/",
};

const char *asciiWaveCrosses[4] = {
	"><><><><",
	"<><><><>",
	"><><><><",
	"<><><><>",
};

const char *asciiWavePulse[4] = {
	"_|'|_|'|",
	"|'|_|'|_",
	"'|_|'|_|",
	"|_|'|_|'",
};

const char *asciiWaveVPulse[4] = {
	"__'___'_",
	"_'___'__",
	"'___'___",
	"___'___'",
};

const char *asciiWaveNoise[4] = {
	"/:./|.:/",
	":./|.:/:",
	"./|.:/:.",
	"/|.:/:./"
};

const char *asciiWaveSilence[4] = {
	"________",
	"________",
	"________",
	"________",
};

const char *asciiWaveIncrement[4] = {
	"_..---''",
	".__---''",
	"...===''",
	"_..---\"\"",
};

const char *asciiWaveDecrement[4] = {
	"\"\"---.._",
	"''===.._",
	"''---__.",
	"''---.._",
};

const char *asciiWaveSaw[4] = {
	"/|/|/|/|",
	"|/|/|/|/",
	"/|/|/|/|",
	"|/|/|/|/",
};

const char *asciiWaveAntiSaw[4] = {
	"\\|\\|\\|\\|",
	"|\\|\\|\\|\\",
	"\\|\\|\\|\\|",
	"|\\|\\|\\|\\",
};

extern int print_piano (int off, int nth, int pressed);
static int lastKey = -1;
static int lastKeyReal = -1;

static bool printPiano(RCore *core) {
	int w = r_cons_get_size (NULL);
	print_piano (keyboard_offset, w / 3, lastKey);
	return true;
}

static bool printWave(RCore *core, int oy) {
	short sample = 0;
	short *words = (short*)core->block;
	// TODO: shift with 'h' and 'l'
	int x , y, h;
	int i, nwords = core->blocksize / 2;
	int w = r_cons_get_size (&h);
#if 0
	h = 20;

	for (y = 0; y<h; y++) {
		for (x = 0; x<w; x++) {
			r_cons_printf ("#");
		}
		r_cons_printf ("\n");
	}
#endif
#if 1
	if (w < 1) w = 1;
	int j, min = 32768; //4200;
	int step = zoomMode? 2: 1;
	if (cursorMode) {
		for (i = 0; i<h; i++) {
			r_cons_gotoxy (cursorPos + 2, i + oy);
			r_cons_printf ("|");
		}
	}
	step *= zoomLevel;
	for (i = j = 0; i < nwords; i += step, j++) {
		int x = j + 2;
		int y = ((words[i]) + min) / 4096;
		if (y < 1) {
			y = 1;
		}
		if (x + 1 >= w) {
			break;
		}
		if (cursorMode && x == cursorPos + 2) {
			r_cons_gotoxy (x - 1, y + 3 + oy);
			r_cons_printf ("[#]");
//			oy = y;
		} else if (cursorMode && x == cursorPos + 3 && y == oy) {
			// do nothing
		} else {
			r_cons_gotoxy (x, y + 3 + oy);
			r_cons_printf (Color_MAGENTA"*"Color_RESET);
		}
		// r_cons_printf ("%d %d - ", x, y);
	}
	r_cons_gotoxy (0, h - 4 + oy);
#endif
	return true;
}

static const char *asciin(int waveType) {
	int mod = waveType % WAVETYPES;
	switch (mod) {
	case SHAPE_SIN: return "sinus";
	case SHAPE_COS: return "cos..";
	case SHAPE_CROSSES: return "cross";
	case SHAPE_TRIANGLE: return "tri..";
	case SHAPE_PULSE: return "pulse";
	case SHAPE_VPULSE: return "vpuls";
	case SHAPE_NOISE: return "noise";
	case SHAPE_SILENCE: return "silen";
	case SHAPE_INC: return "incrm";
	case SHAPE_DEC: return "decrm";
	case SHAPE_SAW: return "saw..";
	case SHAPE_ANTISAW: return "ansaw";
	}
	return NULL;
}

static const char *asciis(int i) {
	int mod = waveType % WAVETYPES;
	i %= 4;
	switch (mod) {
	case SHAPE_SIN: return asciiWaveSin[i];
	case SHAPE_COS: return asciiWaveCos[i];
	case SHAPE_CROSSES: return asciiWaveCrosses[i];
	case SHAPE_TRIANGLE: return asciiWaveTriangle[i];
	case SHAPE_PULSE: return asciiWavePulse[i];
	case SHAPE_VPULSE: return asciiWaveVPulse[i];
	case SHAPE_NOISE: return asciiWaveNoise[i];
	case SHAPE_SILENCE: return asciiWaveSilence[i];
	case SHAPE_INC: return asciiWaveIncrement[i];
	case SHAPE_DEC: return asciiWaveDecrement[i];
	case SHAPE_SAW: return asciiWaveSaw[i];
	case SHAPE_ANTISAW: return asciiWaveAntiSaw[i];
	}
	return NULL;
}

const char **aiis[WAVETYPES] = {
	asciiWaveSin,
	asciiWaveCos,
	asciiWaveCrosses,
	asciiWaveTriangle,
	asciiWavePulse,
	asciiWaveVPulse,
	asciiWaveNoise,
	asciiWaveSilence,
	asciiWaveIncrement,
	asciiWaveDecrement,
	asciiWaveSaw,
	asciiWaveAntiSaw,
};

typedef struct note_t {
	int type;
	int freq;
	int bsize; // TODO
	// TODO: add array of filters like volume, attack, decay, ...
} AUNote;

static AUNote notes[10];

static void au_note_playtone(RCore *core, int note) {
	int idx = notes_index (note, auPianoKeys, keyboard_offset);
	// waveType = notes[note].type;
	float toneFreq = notes_freq (idx);
	char waveTypeChar = WAVECMD[waveType % WAVETYPES];
	r_core_cmdf (core, "auw%c %d", waveTypeChar, (int)toneFreq);
	r_core_cmd0 (core, "au.");
	// r_core_cmd0 (core, "au.&");
}

static void au_note_play(RCore *core, int note, bool keyboard_visible) {
	if (keyboard_visible) {
		lastKey = note;
		lastKeyReal = notes_index (note, auPianoKeys, keyboard_offset) - keyboard_offset;
		au_note_playtone (core, note);
		return;
	}
	waveType = notes[note].type;
	waveFreq = notes[note].freq;
	
	char waveTypeChar = WAVECMD[waveType % WAVETYPES];
	r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
	r_core_cmd0 (core, "au.");
}

static void au_note_set(RCore *core, int note) {
	notes[note].type = waveType;
	notes[note].freq = waveFreq;
}

static bool au_visual_help(RCore *core) {
	r_cons_clear00 ();
	r_cons_printf ("Usage: auv - visual mode for audio processing\n\n");
	r_cons_printf (" jk -> change wave type (sin, saw, ..)\n");
	r_cons_printf (" hl -> seek around the buffer\n");
	r_cons_printf (" HL -> seek faster around the buffer\n");
	r_cons_printf (" R  -> randomize color theme\n");
	r_cons_printf (" n  -> assign current freq+type into [0-9] key\n");
	r_cons_printf (" 0-9-> play and write the recorded note\n");
	r_cons_printf (" +- -> increment/decrement the frequency\n");
	r_cons_printf (" pP -> rotate print modes\n");
	r_cons_printf (" .  -> play current block\n");
	r_cons_printf (" e  -> effect (arpeggio, percent, ...)\n");
	r_cons_printf (" i  -> insert current note in current offset\n");
	r_cons_printf (" :  -> type r2 command\n");

	r_cons_flush (); // use less here
	r_cons_readchar ();
	return true;
}

static void editCycle (RCore *core, int step) {
	// adjust wave (use [] to specify the width to be affected)
	short data = 0;
	r_io_read_at (core->io, core->offset + (cursorPos*2), (ut8*)&data, 2);
	data += step;
	r_io_write_at (core->io, core->offset + (cursorPos*2), (ut8*)&data, 2);

	char *cycle = malloc (cycleSize);
	if (!cycle) {
		return;
	}
	r_io_read_at (core->io, core->offset, (ut8*)cycle, cycleSize);
	int i;
	for (i = cycleSize; i<core->blocksize; i+= cycleSize) {
		r_io_write_at (core->io, core->offset + i, (const ut8*)cycle, cycleSize);
	}
	free (cycle);
	r_core_block_read (core);
	r_core_cmd0 (core, "au.");
}

static const char *phone =
"      _\n"
"  .-'-'---------.\n"
"  |     ==·     |\n"
"  |.-----------.|\n"
"  || dtmf:     ||\n"
"  ||           ||\n"
"  || _________ ||\n"
"  |`-----------'|\n"
"  | [  (   ). ] |\n"
"  | .________   |\n"
"  | |[1][2][3]  |\n"
"  | |[4][5][6]  |\n"
"  | |[7][8][9]  |\n"
"  | |[*][0][#]  |\n"
"  |      _      |\n"
"  `-------------'\n";

static char phone_str[16] = {0};
static void phone_key(RCore *core, const char *ch) {
	strcat (phone_str, ch);
	if (strlen (phone_str) > 9) {
		memmove (phone_str, phone_str + 1, strlen (phone_str)+ 1);
	}
	r_core_cmdf (core, ".(%s)", ch);
}

static void au_setamplitudes(RCore *core, const char *input) {
	char *dinput = strdup (input);
	RList *args = r_str_split_list (dinput, " ", -1);
	RListIter *iter;
	char *arg;
	namplitudes = r_list_length (args);
	int i = 0;
	free (amplitudes);
	amplitudes = calloc (sizeof (int), namplitudes);
	r_list_foreach (args, iter, arg) {
		amplitudes[i++] = (int)r_num_math (core->num, arg);
	}
	r_list_free (args);
	free (dinput);
}

static void au_setchords(RCore *core, const char *input) {
	char *dinput = strdup (input);
	RList *args = r_str_split_list (dinput, " ", -1);
	RListIter *iter;
	char *arg;
	nchords = r_list_length (args);
	int i = 0;
	free (chords);
	chords = calloc (sizeof (int), nchords);
	r_list_foreach (args, iter, arg) {
		chords[i++] = (int)r_num_math (core->num, arg);
	}
	r_list_free (args);
	free (dinput);
}

static bool au_visual_phone(RCore *core) {
	while (1) {
		r_cons_clear00 ();
		r_core_cmd0 (core, "aup");
		r_cons_gotoxy (0, 0);
		r_cons_printf ("[r2phone:0x%08"PFMT64x"]>\n", core->offset);
		r_cons_printf ("%s", phone);
		r_cons_gotoxy (5, 8);
		r_cons_printf ("%10s", phone_str);
		if (*phone_str) {
			r_cons_gotoxy (6 + 9, 8);
		} else {
			r_cons_gotoxy (5 + 9, 8);
		}
		r_cons_flush ();
	//	r_cons_visual_flush ();
		int ch = r_cons_readchar_timeout (500);
		switch (ch) {
		case 'h': if (strlen (phone_str) >0) {phone_str [ strlen (phone_str)-1 ] = 0; } break;
		case 'l': memmove (phone_str, phone_str + 1, strlen (phone_str)); break;
		case 127: *phone_str = 0; break;
		case '1': phone_key (core, "1"); break;
		case '2': phone_key (core, "2"); break;
		case '3': phone_key (core, "3"); break;
		case '4': phone_key (core, "4"); break;
		case '5': phone_key (core, "5"); break;
		case '6': phone_key (core, "6"); break;
		case '7': phone_key (core, "7"); break;
		case '8': phone_key (core, "8"); break;
		case '9': phone_key (core, "9"); break;
		case '*': phone_key (core, "*"); break;
		case '0': phone_key (core, "0"); break;
		case '#': phone_key (core, "#"); break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case 'q':
			return 0;
			break;
		default:
			//printf ("KEY %d %c\n", ch, ch);
			break;
		}
	}
}

static bool au_visual(RCore *core) {
	r_cons_flush ();
	r_cons_print_clear ();
	r_cons_clear00 ();

	ut64 now, base = r_sys_now () / 1000 / 500;
	int otdiff = 0;
	bool keyboard_visible = false;
	while (true) {
		now = r_sys_now () / 1000 / 500;
		int tdiff = now - base;
		const char *wave = asciis (tdiff);
		const char *waveName = asciin (waveType);
		r_cons_clear00 ();
		if (tdiff + 1 > otdiff) {
		//	r_core_cmd (core, "au.", 0);
			if (animateMode) {
				r_core_cmd0 (core, "s+2");
			}
		}
		r_cons_printf ("[r2:auv] [0x%08"PFMT64x"] [%04x] %s %s freq %d block %d cursor %d cycle %d zoom %d\n",
			core->offset, tdiff, wave, waveName, waveFreq, toneSize, cursorPos, cycleSize, zoomLevel);
		int oy, minus = 64;
		if (keyboard_visible) {
			int w = r_cons_get_size (NULL);
			print_piano (keyboard_offset, w / 3, lastKeyReal);
			minus = 128;
			oy = 10;
		} else {
			oy = 0;
		}
		switch (printMode % PRINT_MODES) {
		case 0:
			printWave (core, oy);
			break;
		case 1:
			r_core_cmdf (core, "pze ($r*16)-(%d * 5)", minus);
			printWave (core, oy);
			break;
		case 2:
		//	r_cons_gotoxy (0, 2);
			r_core_cmdf (core, "pze ($r*16)-(%d*3)", minus);
			break;
		case 3:
		//	r_cons_gotoxy (0, 2);
			r_core_cmdf (core, "pxd2 ($r*16)-(%d*3)", minus);
			printWave (core, oy);
			break;
		case 4:
		//	r_cons_gotoxy (0, 2);
			r_core_cmdf (core, "pxd2 ($r*16)-(%d*3)", minus);
			break;
		case 5:
			{
			int zoom = 2;
			r_core_cmdf (core, "p=2 %d @!160", zoom);
			}
			break;
		}
		r_cons_flush ();
	//	r_cons_visual_flush ();
		int ch = r_cons_readchar_timeout (500);
		char waveTypeChar = WAVECMD[waveType % WAVETYPES];
		switch (ch) {
		case '!':
			au_visual_phone (core);
			break;
		case 'a':
			animateMode = !animateMode;
			break;
		case 'p':
			printMode++;
			printMode %= PRINT_MODES;
			break;
		case 'P':
			printMode--;
			printMode %= PRINT_MODES;
			break;
		case 'c':
			cursorMode = !cursorMode;
			break;
		case '1': au_note_play (core, 1, keyboard_visible); break;
		case '2': au_note_play (core, 2, keyboard_visible); break;
		case '3': au_note_play (core, 3, keyboard_visible); break;
		case '4': au_note_play (core, 4, keyboard_visible); break;
		case '5': au_note_play (core, 5, keyboard_visible); break;
		case '6': au_note_play (core, 6, keyboard_visible); break;
		case '7': au_note_play (core, 7, keyboard_visible); break;
		case '8': au_note_play (core, 8, keyboard_visible); break;
		case '9': au_note_play (core, 9, keyboard_visible); break;
		case '0': au_note_play (core, 10, keyboard_visible); break;
		case '=':
			keyboard_visible = !keyboard_visible;
			break;
		case 'n':
			r_cons_printf ("\nWhich note? (1 2 3 4 5 6 7 8 9 0) \n");
			r_cons_flush ();
			int ch = r_cons_readchar ();
			if (ch >= '0' && ch <= '9') {
				au_note_set (core, ch - '0');
			} else if (ch == 'q') {
				// foo
			} else {
				eprintf ("Invalid char\n");
				sleep(1);
			}
			break;
		case 'R':
			// honor real random themes: r_core_cmdf (core, "ecr");
			r_core_cmdf (core, "ecn");
			break;
		case 'f':
			{
				RCons *I = r_cons_singleton ();
				r_line_set_prompt ("(freq)> ");
				I->line->contents = r_str_newf ("%d", toneSize);
				const char *buf = r_line_readline ();
				waveFreq = r_num_math (core->num, buf);
				I->line->contents = NULL;
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case 'b':
			{
				RCons *I = r_cons_singleton ();
				r_line_set_prompt ("audio block size> ");
				I->line->contents = r_str_newf ("%d", toneSize);
				const char *buf = r_line_readline ();
				toneSize = r_num_math (core->num, buf);
				I->line->contents = NULL;
			}
			break;
		case 'K':
			break;
		case 'J':
			break;
		case '*':
			if (cursorMode) {
				editCycle (core, -0x2000);
			} else {
				waveFreq += 100;
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case '/':
			if (cursorMode) {
				editCycle (core, 0x2000);
			} else {
				waveFreq -= 100;
				if (waveFreq < 10) {
					waveFreq = 10;
				}
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case '+':
			if (cursorMode) {
				editCycle (core, -0x1000);
			} else {
				waveFreq += 10;
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case '-':
			if (cursorMode) {
				editCycle (core, 0x1000);
			} else {
				waveFreq -= 10;
				if (waveFreq < 10) {
					waveFreq = 10;
				}
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case 'h':
			if (keyboard_visible) {
				if (keyboard_offset > 0) {
					keyboard_offset --;
					au_note_play (core, 1, keyboard_visible);
				}
				waveFreq = notes_freq (keyboard_offset);
			} else {
				if (cursorMode) {
					if (cursorPos > 0) {
						cursorPos--;
					}
				} else {
					r_core_seek_delta (core, -2);
					r_core_cmd0 (core, "au.");
				}
			}
			break;
		case 'l':
			if (keyboard_visible) {
				keyboard_offset ++;
				waveFreq = notes_freq (keyboard_offset);
				if (waveFreq) {
					au_note_play (core, 1, keyboard_visible);
				} else {
					keyboard_offset --;
				}
			} else {
				if (cursorMode) {
					cursorPos++;
				} else {
					r_core_seek_delta (core, 2);
					r_core_cmd0 (core, "au.");
				}
			}
			break;
		case 'H':
			if (keyboard_visible) {
				if (keyboard_offset > 0) {
					keyboard_offset -= 6;
					if (keyboard_offset < 0) {
						keyboard_offset = 0;
					}
				}
				waveFreq = notes_freq (keyboard_offset);
				au_note_play (core, 1, keyboard_visible);
			} else {
				// r_core_seek_delta (core, -toneSize); // zoomMode? -512: -128);
				r_core_cmd0 (core, "s--");
				r_core_cmd0 (core, "au.");
			}
			break;
		case 'L':
			if (keyboard_visible) {
				keyboard_offset += 6;
				while (!notes_freq (keyboard_offset)) {
					keyboard_offset --;
					if (keyboard_offset < 0) {
						break;
					}
				}
				waveFreq = notes_freq (keyboard_offset);
				au_note_play (core, 1, keyboard_visible);
			} else {
				// r_core_seek_delta (core, toneSize); // zoomMode? 512: 128);
				r_core_cmd0 (core, "s++");
				r_core_cmd0 (core, "au.");
			}
			break;
		case 'z':
			zoomMode = !zoomMode;
			break;
		case 'j':
			if (cursorMode) {
				editCycle (core, 0x1000);
			} else {
				waveType++;
				playNote (core);
			}
			break;
		case 'e':
			auEffect ++;
			if (auEffect >= EFFECT_LAST) {
				auEffect = 0;
			}
			playNote (core);
			break;
		case '?':
			au_visual_help (core);
			break;
		case 'k':
			if (cursorMode) {
				editCycle(core, -0x1000);
			} else {
				waveType--;
				if (waveType < 0) {
					waveType = 0;
				}
				waveTypeChar = WAVECMD[waveType % WAVETYPES];
				r_core_cmdf (core, "auw%c %d", waveTypeChar, waveFreq);
				r_core_cmd0 (core, "au.");
			}
			break;
		case 'i':
			r_core_cmdf (core, "auws %d", waveFreq);
			break;
		case '[':
			if (cursorMode) {
				cycleSize -= 2;
				if (cycleSize < 0) {				
					cycleSize = 0;
				}
				editCycle (core, 0);
			} else {
				zoomLevel--;
				if (zoomLevel < 1) {
					zoomLevel = 1;
				}
			}
			break;
		case ']':
			if (cursorMode) {
				cycleSize += 2;
				if (cycleSize < 0) {				
					cycleSize = 0;
				}
				editCycle (core, 0);
			} else {
				zoomLevel++;
			}
			break;
		case '.':
			// TODO : run in a thread?
			r_core_cmd0 (core, "au.");
			break;
		case 'q':
			if (keyboard_visible) {
				keyboard_visible = false;
			} else {
				return false;
			}
			break;
		}
	}
	
	return false;
}

static bool au_play(RCore *core) {
	ao_play (device, (char *)core->block, core->blocksize);
	// eprintf ("Played %d bytes\n", core->blocksize);
	return false;
}

static int _cmd_au (RCore *core, const char *args) {
	switch (*args) {
	case 'i': // "aui"
		// setup arguments here
		{
			char *arg_freq = strchr (args, ' ');
			int rate = WAVERATE;
			int bits = WAVEBITS;
			int chan = 1;
			if (arg_freq) {
				char *arg_bits = strchr (arg_freq + 1, ' ');
				*arg_freq++ = 0;
				rate = r_num_math (core->num, arg_freq);
				if (arg_bits) {
					*arg_bits++ = 0;
					char *arg_chans = strchr (arg_bits, ' ');
					bits = r_num_math (core->num, arg_bits);
					if (arg_chans) {
						*arg_chans++ = 0;
						chan = r_num_math (core->num, arg_chans);
					}
				}
			}
			int be = r_config_get_i (core->config, "cfg.bigendian");
			// TODO: register 'e au.rate' 'au.bits'... ?
			eprintf ("[au] %d Hz %d bits %d channels\n", rate, bits, chan);
			au_init (rate, bits, chan, be);
			// ao_play (device, (char *)core->block, core->blocksize);
		}
		break;
	case 'n': // "aun" [noisetype]
		if (strstr (args, "white")) {
			noiseType = NOISE_WHITE;
		} else if (strstr (args, "pink")) {
			noiseType = NOISE_PINK;
		} else if (strstr (args, "brown")) {
			noiseType = NOISE_BROWN;
		} else {
			switch (noiseType) {
			case NOISE_WHITE:
				r_cons_printf ("white\n");
				break;
			case NOISE_PINK:
				r_cons_printf ("pink\n");
				break;
			case NOISE_BROWN:
				r_cons_printf ("brown\n");
				break;
			}
		}
		break;
	case 'm': // "aum"
		// write pattern here
		{
			captureBlocksize ();
			au_mix (core, args + 1);
			r_core_block_read (core);
			restoreBlocksize ();
		}
		break;
	case 't': // "aut"
		{
			const char *frate = "2256";
			switch (format.rate) {
			case 44100: frate = "44ac"; break;
			case 22050: frate = "2256"; break;
			case 11025: frate = "112b"; break;
			}
			r_core_cmdf (core, "wx 52494646c657050057415645666d74201000000001000100"
				"%s"
				"000088580100020010004c4953541a000000494e464f495346540e0000004c61766635382e31322e3130300064617461805705004e03"
				, frate);
		}
		break;
	case 'w': // "auw"
		// write pattern here
		{
		captureBlocksize();
		au_write (core, args + 1);
		r_core_block_read (core);
		restoreBlocksize();
		}
		break;
	case 'b': // "aub"
		if (args[1] == ' ') {
			aBlocksize = r_num_math (core->num, args + 2);
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", aBlocksize);
		}
		break;
	case 'o': // "auo"
		if (args[1]) {
			captureBlocksize();
			au_operate (core, args + 1);
			r_core_block_read (core);
			restoreBlocksize();
		} else {
			eprintf ("Usage: auo[+-*/] [val]\n");
		}
		break;
	case 'a': // "aua"
		au_anal (core, args + 1);
		break;
	case 'p': // "aup"
		switch (args[1]) {
		case 'p':
		case 'i':
			printPiano (core);
			break;
		case '?':
			eprintf ("Usage: aup[p] arg\n");
			break;
		default:
			printWave (core, 0);
			break;
		}
		break;
	case '.': // "au."
		if (args[1] == '&') {
			eprintf ("Temporal magic\n");
		} else if (args[1] == ' ') {
			int i, rep = r_num_math (core->num, args + 2);
			r_cons_break_push (NULL, NULL);
			for (i = 0; i<rep ; i++) {
				r_cons_is_breaked ();
				au_play (core);
				r_sys_usleep (500);
			}
			r_cons_break_pop ();
		} else {
			captureBlocksize();
			au_play (core);
			restoreBlocksize();
		}
		break;
	case 'E': // "auE"
		au_setchords (core, r_str_trim_head_ro (args + 1));
		break;
	case 'N': // "auN"
		au_setamplitudes (core, r_str_trim_head_ro (args + 1));
		break;
	case 'e': // "aue"
		switch (args[1]) {
		case 'p':
			auEffect = EFFECT_PERCENT;
			break;
		case 'a':
			auEffect = EFFECT_ARPEGGIO;
			break;
		case 0:
			auEffect = EFFECT_NONE;
			break;
		default:
			eprintf ("Usage: auep -> percent effect, auea -> arpeggio effect\n");
			break;
		}
		break;
	case 'f': // "auf"
		if (args[1] == ' ') {
			int idx = r_num_math (core->num, args + 1);
			if (idx >= 0 && idx < TONES) {
				r_cons_printf ("%d\n", (int)tones[idx].freq);
			}
		} else {
			for (int i = 0; i < TONES; i++) {
				char note[32], *dolar;
				strcpy (note, tones[i].note);
				dolar = strchr (note, '$');
				if (dolar) {
					*dolar = '_';
				}
				r_cons_printf ("f tone.%s = %d # %d\n", note, (int)tones[i].freq, i);
			}
		}
		break;
	case 'v': // "auv"
		au_visual (core);
		break;
	default:
	case '?':
		eprintf ("Usage: au[.abfeEimopvw] [args]\n");
		eprintf (" au. - play current block (au.& in bg)\n");
		eprintf (" aua - analyze wave in current block\n");
		eprintf (" aub - audio blocksize\n");
		eprintf (" auf - flags per freqs associated with keys\n");
		eprintf (" aue - audio effects (arpeggio, percent, ..)\n");
		eprintf (" auE [arpeggio] - arpeggio chords to use\n");
		eprintf (" aui - init audio\n");
		eprintf (" aum - mix from given address into current with bsize\n");
		eprintf (" aun [noisetype] - select [white, pink, brown]\n");
		eprintf (" auN [amplitudes] - space separated volume changes 100 = 1\n");
		eprintf (" auo - apply operation with immediate\n");
		eprintf (" aup - print wave (aupi print piano)\n");
		eprintf (" auv - visual wave mode\n");
		eprintf (" auw - write wave (see auw?)\n");
		break;
	}
	return false;
}

static int r_cmd_au_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, "au", 2)) {
		_cmd_au (core, input + 2);
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_au = {
	.name = "audio",
	.desc = "play mustic with radare2",
	.license = "MIT",
	.call = r_cmd_au_call,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_au,
	.version = R2_VERSION
};
#endif

