/* radare - LGPL-3.0-only - Copyright 2026 - pancake */
#ifndef R2_QJS_H
#define R2_QJS_H
#include <r_util.h>

#ifndef SHORT_OPCODES
#define SHORT_OPCODES 1
#endif

typedef struct {
	const char *name;
	const char *fmt;
	ut8 size, pop, push;
} QjsOpcode;

static const QjsOpcode qjs_opcodes[] = {
#define def(id, size, pop, push, fmt)
#define DEF(id, size, pop, push, fmt) { #id, #fmt, size, pop, push },
#include <quickjs-opcode.h>
};

static inline const QjsOpcode *qjs_opcode(ut8 code) {
	return code && code < R_ARRAY_SIZE (qjs_opcodes)? &qjs_opcodes[code]: NULL;
}

// Describe operands by width; negative widths are signed, labels are PC relative.
static inline int qjs_operands(const QjsOpcode *o, int widths[3], int *label) {
	const char *f = o->fmt;
	*label = -1;
	widths[0] = widths[1] = widths[2] = 0;
	if (!strncmp (f, "none", 4) || !strcmp (f, "npopx")) {
		return 0;
	}
	if (!strcmp (f, "atom_label_u8") || !strcmp (f, "atom_label_u16")) {
		widths[0] = 4;
		widths[1] = -4;
		widths[2] = !strcmp (f, "atom_label_u8")? 1: 2;
		*label = 1;
		return 3;
	}
	if (!strcmp (f, "atom_u8") || !strcmp (f, "atom_u16") || !strcmp (f, "npop_u16") || !strcmp (f, "label_u16") || !strcmp (f, "u32x2")) {
		widths[0] = !strcmp (f, "npop_u16")? 2: 4;
		widths[1] = !strcmp (f, "atom_u8")? 1: !strcmp (f, "u32x2")? 4: 2;
		if (!strcmp (f, "label_u16")) {
			widths[0] = -4;
			*label = 0;
		}
		return 2;
	}
	if (!strcmp (f, "label") || !strcmp (f, "label8") || !strcmp (f, "label16")) {
		widths[0] = -(o->size - 1);
		*label = 0;
	} else {
		widths[0] = o->size - 1;
		if (*f == 'i') {
			widths[0] = -widths[0];
		}
	}
	return 1;
}

static inline st64 qjs_read(const ut8 *b, int width, bool be) {
	ut64 n = r_read_ble (b, be, abs (width) * 8);
	if (width < 0) {
		int shift = 64 + width * 8;
		return (st64)(n << shift) >> shift;
	}
	return n;
}
#endif
