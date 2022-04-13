#include <r_util.h>

// https://en.wikipedia.org/wiki/Colors_of_noise

// TODO: add support for red, green, blue, violet, grey, black (silence), 

void noise_pink(ut8 *buf, int buflen) {
	int i;
	double b0 = 0;
	double b1 = 0;
	double b2 = 0;
	double b3 = 0;
	double b4 = 0;
	double b5 = 0;
	double b6 = 0;
	short *output = (short*)buf;
	int bufferSize = buflen / sizeof (short);
        for (i = 0; i < bufferSize; i++) {
            double white = (double)(rand () % 32000) - 1;
            b0 = 0.99886 * b0 + white * 0.0555179;
            b1 = 0.99332 * b1 + white * 0.0750759;
            b2 = 0.96900 * b2 + white * 0.1538520;
            b3 = 0.86650 * b3 + white * 0.3104856;
            b4 = 0.55000 * b4 + white * 0.5329522;
            b5 = -0.7616 * b5 - white * 0.0168980;
            double res = b0 + b1 + b2 + b3 + b4 + b5 + b6 + white * 0.5362;
            output[i] = (short) res * 0.1; // compensate for gain
            b6 = white * 0.115926;
        }
}

void noise_brown(ut8 *buf, int buflen) {
	double lastOut = 0.0;
	short *output = (short*)buf;
	int bufferSize = buflen / sizeof (short);
	int i;
        for (i = 0; i < bufferSize; i++) {
            double white = (double)(rand () % 32000) - 1;
            double tmp = (lastOut + (0.02 * white)) / 1.02;
            lastOut = tmp;
            output[i] = (tmp * 3.5); // (roughly) compensate for gain
        }
}
