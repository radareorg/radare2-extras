/* radare - LGPL - Copyright 2015-2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const char *bases = "ACGT";
	if (a->pc == 0) {
		ut32 *clusters = (ut32*)buf;
		r_strbuf_setf (&op->buf_asm, "clusters %d", *clusters);
		// snprintf (op->buf_asm, sizeof (op->buf_asm), "clusters %d\n", *clusters);
		return op->size = 4;
	}
	if (*buf != 0) {
		char base = bases[*buf & 3];
		int qual = *buf >> 2;
		r_strbuf_setf (&op->buf_asm, "%c ; %d", base, qual);
		op->size = 1;
		return 1;
	}
	r_strbuf_setf (&op->buf_asm, ".");
	return 0;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
#if 0
	bool qmode = false;
	int quality = 0;
	int outsz = 128;
	int count = 0;
	int base = 0;
	char *out = (char *)op->buf;
	for (; *buf; buf++) {
		switch (*buf) {
		case 'a':
		case 'A':
			base = 0;
			break;
		case 'c':
		case 'C':
			base = 1;
			break;
		case 'g':
		case 'G':
			base = 2;
			break;
		case 't':
		case 'T':
			base = 3;
			break;
		case ' ':
			qmode = true;
			break;
		default:
			if (qmode) {
				if (op->size>=outsz) {
					eprintf ("too big\n");
					free (out);
					op->size = 0;
					return 0;
				}
				quality = atoi (buf);
				out[op->size] = (atoi (buf)<<2) | base;
				while (*buf) {
					char ch = *buf;
					if (ch>='0' && ch<='9') {
						buf++;
						continue;
					}
					break;
				}
				qmode = false;
			}
			break;
		}
		out[op->size] = (quality<<2) | base;
		op->size ++;
	}
#endif
	return op->size;
}

RAsmPlugin r_asm_plugin_bcl = {
	.name = "bcl",
	.desc = "Base Call Quality DNA disassembler - Illumina raw data",
	.license = "BSD",
	.arch = "bcl",
	.bits = 8,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bcl,
	.version = R2_VERSION
};
#endif
