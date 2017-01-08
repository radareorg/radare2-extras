/* radare - LGPL - Copyright 2014 - pancake */
#if 0
gcc -o core_test.so -fPIC `pkg-config --cflags --libs r_core` core_test.c -shared
mkdir -p ~/.config/radare2/plugins
mv core_test.so ~/.config/radare2/plugins
#endif

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static int mycall(void *user, const char *input) {
	int i, j;
	const int seqsz = 100;
	int data[seqsz];
	RCore *core = (RCore *) user;
	if (!strncmp (input, "pbc", 3)) {
		char lala = input[3];
		int newsize, bsize;
		int in_color = r_config_get_i (core->config, "scr.color");
		const char *bases = "ACGT";
		newsize = bsize = core->blocksize;
		if (!lala) return false;
		if (input[4] == ' ') {
			newsize = (int)r_num_math (core->num, input+4);
		}
		if (newsize != bsize) {
			r_core_block_size (core, newsize);
		}
		for (j=0;j<seqsz;j++) {
			data[j] = 0;
		}
		r_cons_printf ("0x%08"PFMT64x"  ", core->offset);
		for (i=0; i<core->blocksize; i++) {
			char idx = core->block[i] & 3;
			char b = bases[idx];
			data[i%seqsz] = core->block[i] >> 2;
			if (in_color) {
				r_cons_printf("\x1b[3%cm%c\x1b[0m", '1' + idx, b);
			} else {
				r_cons_printf("%c", b);
			}
			if (i && !((i+1) % seqsz) && i+1<core->blocksize) {
				if (lala=='L') {
					r_cons_printf("\n++++++++++  ");
					for (j=0; j<seqsz; j++) {
						r_cons_printf("%c", '!' + data[j]);
					}
				}
				r_cons_printf ("\n0x%08"PFMT64x"  ", core->offset + i);
			}
		}
		if (lala=='L') {
			r_cons_printf("\n++++++++++  ");
			int sz = core->blocksize % seqsz;
			if (!sz) sz = seqsz;
			for (j=0; j<sz; j++) {
				r_cons_printf("%c", '!' + data[j]);
			}
			r_cons_printf("\n");
		}
		if (newsize != bsize) {
			r_core_block_size (core, bsize);
		}
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_test = {
	.name = "bcl",
	.desc = "BaseCall commands",
	.license = "BSD",
	.call = mycall,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_test,
	.version = R2_VERSION
};
#endif
