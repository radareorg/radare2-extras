// #include "windows.h"
#include "ao.h"
#include <stdio.h>
#include <string.h>
#define _USE_MATH_DEFINES
#include <math.h>

#define BUF_SIZE 512 

ao_sample_format format;
ao_device *device;

enum {
	FORM_SIN,      // .''.''.
	FORM_COS,      // '..'..'
	FORM_SAW,      // /|/|/|/
	FORM_PULSE,    // |_|'|_|
	FORM_NOISE,    // \:./|.:
	FORM_TRIANGLE, // /\/\/\/
	FORM_SILENCE,  // ______
	FORM_INC,      // _..--''
	FORM_DEC,      // ''--.._
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

int sample_crop(short *buf, int size, int newsize) {
	int isize = size / 2;
	int i, lastMatch = -1;
	int first = buf[0];
	// return newsize;
	for (i = 0; i + 1< isize; i++) {
		if (buf[i] == first) {
			lastMatch = i + 1;
		}
		if (i >= newsize) {
			if (lastMatch != -1) {
				return lastMatch * 2;
			}
			return (i * 2);
		}
	}
	return size;
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
			}
			else {
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
		}
		else {
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
		}
		else {
			for (i = 0; i < isize; i++) {
				if (ibuf[i] < 0) {
					ibuf[i] = 0;
				}
			}
		}
		break;
	case FILTER_ROTATE:
		if (value > 0) {
			short *tmp = calloc(sizeof(short), value);
			for (i = 0; i< value; i++) {
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
		else {
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
		}
		else {
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

void sample_add(char *buf, char *obuf, int size) {
	int i;
	short *ibuf = (short*)buf;
	short *iobuf = (short*)obuf;
	for (i = 0; i < size / 2; i++) {
		ibuf[i] = (ibuf[i] + iobuf[i]) / 2;
	}
}

void sample_play(char *buf, int len, int duration) {
	if (duration < 1) {
		duration = len;
	}
	if (duration < len) {
		int pc = (int)((float)len * (float)duration / 100.0);
		int cropped_size = sample_crop((short*)buf, len, pc);
		ao_play(device, buf, cropped_size);
	} else {
		int i;
		for (i = 0; i < duration; i += len) {
			if (i + len < duration) {
				len = duration - i;
			}
			ao_play(device, buf, len);
		}
	}
}

char *sample_new(float freq, int form, int *size) {
	int i;
	short sample;
	float max_sample = 0x00ff; // format.bits == 16 ? 0xffff / 2 : 0xff / 2;
	float volume = 0.5;
	float pc;
	// int buf_size = format.bits / 8 * format.channels * format.rate;
	int buf_size = 16 / 8 * format.channels * format.rate;
	char *buffer = calloc (buf_size, sizeof (char));
	if (size) {
		*size = buf_size;
	}
	for (i = 0; i < format.rate; i++) {
		sample = (char)(max_sample * sin(2 * M_PI * freq * ((float)i / format.rate * 2)));
		switch (form) {
		case FORM_SILENCE:
			sample = 0;
			break;
		case FORM_DEC:
		case FORM_INC:
			pc = (float)i / (float)format.rate * 100;
			if (form == FORM_INC) {
				pc = 100 - pc;
			}
			pc /= 11; // step -- should be parametrizable
			pc += 1;
			if (!((int)i % (int)pc)) {
				sample = max_sample;
			} else {
				sample = -max_sample;
			}
			break;
		case FORM_COS:
			sample = (int)(max_sample * cos (2 * M_PI * freq * ((float)i / format.rate * 2)));
			break;
		case FORM_SIN:
			// do nothing
			break;
		case FORM_SAW:
			{
				int rate = 14000 / freq;
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
				// printf ("%f\n", (float)sample);
			}
			break;
		case FORM_TRIANGLE:
			{
				int rate = (14000 / freq) * 2;
				sample = ((i % rate) * (max_sample * 2) / rate) - max_sample;
			}
			break;
		case FORM_PULSE:
			sample = sample > 0 ? max_sample : -max_sample;
			break;
		case FORM_NOISE:
			sample = (rand() % (int)(max_sample * 2)) - max_sample;
			break;
		}
		sample *= volume;
// printf ("SAMP %d\n", sample >> 8);
		/* left channel */
		buffer[2 * i] = sample & 0xf;
		buffer[2 * i + 1] = (sample >> 4) & 0xff;
		// buffer[(2 * i) + 1] = ((unsigned short)sample >> 8) & 0xff;
		i++;
	}
	return buffer;
}

int play_scale(int m) {
	int size;
	char *sample = sample_new (800, FORM_SIN, &size);
	sample_filter(sample, size, FILTER_DEC, 8);
	sample_filter(sample, size, FILTER_VOLUME, 20);
	sample_filter(sample, size, FILTER_ATTACK, 4);
	sample_filter(sample, size, FILTER_SCALE, 8);
	if (m) {
		sample_filter(sample, size, FILTER_DECAY, 10);
		sample_filter(sample, size, FILTER_VOLUME, 100);
	}
	sample_play(sample, size, 0);
	free(sample);
	if (m) {
		sample = sample_new(0, FORM_SILENCE, &size);
		sample_play(sample, size, -1);
		free(sample);
	}
	return 0;
}

int play_coin() {
	int size;
	char *sample = sample_new(1500, FORM_SIN, &size);
	sample_play(sample, size, 4);
	free(sample);

	sample = sample_new(1800, FORM_SIN, &size);
	sample_play(sample, size, 4);
	free(sample);

	sample = sample_new(2200, FORM_SIN, &size);
	sample_filter(sample, size / 2, FILTER_DECAY, 10);
	sample_play(sample, size, 48);
	free(sample);

	sample = sample_new(0, FORM_SILENCE, &size);
	sample_play(sample, size, -1);
	free(sample);
	return 0;
}

int play_freq2(float freq, int form) {
	int size;
	char *sample = sample_new(freq, form, &size);

	sample_filter (sample, size / 2, FILTER_DECAY, 10);
	char *s = sample_new (freq, FORM_SAW, &size);
	sample_add (sample, s, size);
#if 0
	char *sample2 = sample_new(freq, FORM_NOISE, &size);
	sample_filter(sample2, size, FILTER_VOLUME, 60);
	//sample_filter (sample2, size, FILTER_MOD, 2000);
	sample_add(sample, sample2, size);
	sample_filter(sample, size, FILTER_SIGN, 1);
#endif
	sample_play(sample, size, 10);
	free(sample);
	// free (sample2);
	return 0;
}

int play_freq(float freq, int form, int speed) {
	int size;
	if (format.bits < 16) {
		speed /= 2;
	}
	char *sample = sample_new(freq, form, &size);
printf ("FREQ %f %d %d\n", freq, form, speed);
	char *sample2 = sample_new(freq, FORM_PULSE, &size);
	//sample_filter (sample, size, FILTER_INTERLACE, 100);
	//sample_filter (sample2, size, FILTER_INVERT, 20);
	//sample_filter (sample2, size, FILTER_ROTATE, 20);
	sample_filter(sample2, size, FILTER_SCALE, 2);
	sample_filter(sample2, size, FILTER_VOLUME, 60);
	sample_filter(sample2, size, FILTER_SHIFT, 85);
	//sample_filter (sample2, size, FILTER_MOD, 2000);
	sample_add (sample, sample2, size);
	sample_filter (sample, size, FILTER_SIGN, 1);
	sample_play (sample, size, speed);
	free (sample);
	free (sample2);
	return 0;
}

int piano[] = {
	61,
	65,
	73,
	77,
	82,
	97,
	110,
	123,
	130,
	146,
	164,
	174,
	195,
	220,
	246,
	246,
	261,
	293,
	329,
	349,
	391,
	440,
	493,
	523,
	0
};

int song[] = {
	0,0,2,0,0,2,0,0,0,2,0,13,3,
	-1
};

#if 0
Assembly proposal
== == == == == == == == =

mkw s0, 0, 1500
play s0

alw s0, 0
alw s1, 0
mov r0, 3
back:
mkw s0, FORM_SIN, 2600
flw s0, FILTER_DECAY, 30
mkw s1, FORM_SIN, 2000
add s0, s1, 1
ps s0, s0s, 0
loop r0, back
done :
frw s0
frw s1

#endif
int main() {
	int default_driver;
	int sample2;
	//float freq = 440.0;
	float freq = 7600;
	// iona 40 - 14000
	// apap 40 - 15000
	int i;

	ao_initialize();

	default_driver = ao_default_driver_id();

	memset (&format, 0, sizeof (format));
	format.bits = 8; // SID is 16bit, 8bit sounds too much like PDP
	// format.bits = 8; // SID is 16bit, 8bit sounds too much like PDP
	format.channels = 1;
	// format.rate = 22050;
	format.rate = 11025;
	format.byte_format = AO_FMT_LITTLE;

	device = ao_open_live(default_driver, &format, NULL /* no options */);
	if (device == NULL) {
		fprintf(stderr, "Error opening device.\n");
		return 1;
	}


//	play_scale(0);

	// play_scale(1);
	// chime
	play_coin();

	int loop;
	for (loop = 0; loop < 2; loop++) {
		for (i = 0; i < 100; i++) {
			if (-1 == song[i]) {
				break;
			}
			play_freq (piano[song[i]], FORM_COS, 24);
		}
	}
	for (i = 0; i < 3; i++) {
		play_freq2 (0, FORM_NOISE);
	}
	for (loop = 0; loop < 2; loop++) {
		for (i = 0; i < 100; i++) {
			if (-1 == song[i]) {
				break;
			}
			play_freq (piano[song[i]] * 2, FORM_PULSE, 20);
		}
	}
	play_freq2 (0, FORM_NOISE);

	ao_close (device);
	ao_shutdown ();
	return 0;
}
