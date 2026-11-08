/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* Linear sweep of a raw file with the plugin decoder, one line per instruction:
 *   offset <TAB> size <TAB> row <TAB> mnemonic <TAB> text
 * usage: mn103-dis [-c mn10300|am30|am33|am33-2] [-b base] file */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mn103_decode.h"

int main(int argc, char **argv) {
	int mach = MN103_MACH_AM33_2;
	ut64 base = 0;
	int i;
	const char *path = NULL;
	for (i = 1; i < argc; i++) {
		if (!strcmp (argv[i], "-c") && i + 1 < argc) {
			const char *c = argv[++i];
			mach = !strcmp (c, "mn10300")? MN103_MACH_BASE: !strcmp (c, "am30")? MN103_MACH_AM30:
				!strcmp (c, "am33")? MN103_MACH_AM33: MN103_MACH_AM33_2;
		} else if (!strcmp (argv[i], "-b") && i + 1 < argc) {
			base = strtoull (argv[++i], NULL, 0);
		} else {
			path = argv[i];
		}
	}
	if (!path) {
		fprintf (stderr, "usage: mn103-dis [-c cpu] [-b base] file\n");
		return 1;
	}
	FILE *f = fopen (path, "rb");
	if (!f) {
		perror (path);
		return 1;
	}
	fseek (f, 0, SEEK_END);
	long n = ftell (f);
	fseek (f, 0, SEEK_SET);
	ut8 *buf = malloc (n > 0? n: 1);
	if (!buf || fread (buf, 1, n, f) != (size_t)n) {
		fclose (f);
		free (buf);
		return 1;
	}
	fclose (f);
	long off = 0;
	while (off < n) {
		Mn103Insn in;
		const bool ok = mn103_decode (&in, buf + off, (int)(n - off), base + off, mach);
		const int size = in.size > 0? in.size: 1; /* the binutils length rule, also for an unknown opcode */
		RStrBuf sb;
		r_strbuf_init (&sb);
		mn103_format (&sb, &in);
		printf ("%llx\t%d\t%d\t%s\t%s\n", (unsigned long long)(base + off), size, ok? in.index: -1,
			ok? in.desc->name: "unknown", r_strbuf_get (&sb));
		r_strbuf_fini (&sb);
		off += size;
	}
	free (buf);
	return 0;
}
