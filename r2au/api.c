int aoc_emu(const ut8 *buf, int len) {
	const int op = buf[0];
	switch (op) {
	case AOC_OP_MKW:
		eprintf ("makewave\n");
		break;
	case AOC_OP_PS:
		eprintf ("playsample\n");
		break;
	}
	return 0;
}

int aoc_disasm(const ut8 *buf, int len) {
	const int op = buf[0];
	switch (op) {
	case AOC_OP_MKW:
		break;
	case AOC_OP_PS:
		break;
	}
	return 0;
}

int aoc_asm(const char *str, OUT ut8 *data, int *data_len) {
	return -1;
}

