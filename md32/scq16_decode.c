/* scq16_decode.c - decoder of the SCQ16: the length and packet rule by bit leaves + the forms of scq16_opcodes.h.
 * See scq16_decode.h.  C99 without dependencies (included by scq16_arch.inc.c). */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "scq16_decode.h"

/* ------------------------------------------------------------------------------------------------ leaves --------- */
static int scq16_leaf_lookup(const Scq16Leaf *leaves, const uint16_t *start, uint8_t b0, uint8_t b1) {
	int best_depth = -1, best = 0, i;
	for (i = start[b0]; i < start[b0 + 1]; i++) {
		const Scq16Leaf *l = &leaves[i];
		if (l->depth == 0 || (b1 >> (8 - l->depth)) == l->prefix) {
			if (l->depth > best_depth) {
				best_depth = l->depth;
				best = l->label;
			}
		}
	}
	return best_depth < 0 ? 0 : best;
}

int scq16_uleaf(uint8_t b0, uint8_t b1) {
	return scq16_leaf_lookup (scq16_uleaves, scq16_uleaf_start, b0 & 0x7f, b1);
}

int scq16_hleaf(uint8_t a0, uint8_t a1) {
	if (a0 >= 0x80) {
		return 0;
	}
	return scq16_leaf_lookup (scq16_hleaves, scq16_hleaf_start, a0, a1);
}

/* ------------------------------------------------------------------------------------------------ unit ----------- */
static uint64_t scq16_be_int(const uint8_t *b, int L) {
	uint64_t w = 0;
	int i;
	for (i = 0; i < L; i++) {
		w = (w << 8) | b[i];
	}
	return w;
}

static int32_t scq16_operand_value(const Scq16Operand *op, uint64_t w) {
	uint32_t v = 0;
	int width = 0, i;
	if (op->kind == SCQ16_O_CONST) {
		return op->cval;
	}
	for (i = 0; i < op->npieces; i++) {
		v = (v << op->piece[i].w) | (uint32_t)((w >> op->piece[i].lo) & ((1ULL << op->piece[i].w) - 1));
		width += op->piece[i].w;
	}
	int64_t s = v;
	if (op->is_signed && width < 32 && (v >> (width - 1))) {
		s = (int64_t)v - (1LL << width);
	} else if (op->is_signed && width == 32) {
		s = (int32_t)v;
	}
	s = s * op->scale + op->bias;
	if (op->kind == SCQ16_O_R4P || op->kind == SCQ16_O_R3P) {
		s += 1;
	}
	return (int32_t)s;
}

static void scq16_decode_unit_alt(Scq16Unit *u, const uint8_t *b, int L, uint32_t pc, uint32_t base, uint8_t slot, const Scq16Alt *force) {
	const uint16_t *idx = NULL;
	int n = 0, i;
	memset (u, 0, sizeof (*u));
	u->pc = pc; u->L = L; u->slot = slot; u->base = base;
	memcpy (u->b, b, L);
	u->w = scq16_be_int (b, L);
	if (force) {
		if ((u->w & force->mask) == force->value) {
			u->alt = force;
		}
		goto operands;
	}
	switch (L) {
	case 2: idx = scq16_alts_L2; n = SCQ16_NALTS_L2; break;
	case 3: idx = scq16_alts_L3; n = SCQ16_NALTS_L3; break;
	case 4: idx = scq16_alts_L4; n = SCQ16_NALTS_L4; break;
	case 5: idx = scq16_alts_L5; n = SCQ16_NALTS_L5; break;
	case 6: idx = scq16_alts_L6; n = SCQ16_NALTS_L6; break;
	case 8: idx = scq16_alts_L8; n = SCQ16_NALTS_L8; break;
	default: return;
	}
	for (i = 0; i < n; i++) {
		const Scq16Alt *a = &scq16_alts[idx[i]];
		if ((u->w & a->mask) == a->value) {
			u->alt = a;
			break;
		}
	}
operands:
	if (!u->alt) {
		return;
	}
	for (i = 0; i < u->alt->nops && i < SCQ16_MAX_OPS; i++) {
		const Scq16Operand *op = &u->alt->ops[i];
		int32_t v = scq16_operand_value (op, u->w);
		if (op->kind == SCQ16_O_DISP) {
			v = (int32_t)(base + (uint32_t)v);
			u->has_target = true;
			u->target = (uint32_t)v;
		}
		u->vals[i] = v;
	}
	u->nvals = u->alt->nops;
	if (u->alt->kind == SCQ16_K_VEC && (L == 4 || L == 8) && (u->alt->form_name[0] == 'v' && (u->alt == &scq16_alts[SCQ16_VEC_ALT] || u->alt == &scq16_alts[SCQ16_BUNDLE_ALT]))) {
		u->vec32 = (L == 8) ? (uint32_t)((u->w >> 30) & 0xffffffffULL) : (uint32_t)u->w;
		u->op9 = u->vec32 & 0x1ff;
	}
}

void scq16_decode_unit(Scq16Unit *u, const uint8_t *b, int L, uint32_t pc, uint32_t base, uint8_t slot) {
	scq16_decode_unit_alt (u, b, L, pc, base, slot, NULL);
}

static void scq16_shift_bytes(uint8_t *dst, const uint8_t *src, int L, int nb) {
	int i;
	for (i = 0; i < L; i++) {
		dst[i] = (uint8_t)((src[i] << 1) | (i + 1 < L ? (src[i + 1] >> 7) : nb));
	}
}

static int scq16_need(Scq16Insn *out, int n) {
	out->size = 0;
	out->need = n;
	return 0;
}

/* j.d1 56 0x-3x: with a function table at hand the length is decided by context (4 bytes only when the 22-bit target falls
 * inside a known function); the plugin has no function table and decides BY TARGET: the 2-byte reading has no form and the 4-byte one is j.d1 with
 * target base + simm22, taken when that target is a plausible code address (no wrap below 0 and within SCQ16_JD1_REACH).  The
 * leaves 56 03 / 56 3f of the length table are subsumed. */
#ifndef SCQ16_JD1_REACH
#define SCQ16_JD1_REACH 0x400000u
#endif
static int scq16_jd1_len(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, int avail, uint32_t base, int leaf) {
	if (avail < 4 || b0 != 0x56 || (b1 >> 6) != 0) {
		return leaf;
	}
	uint32_t w = ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
	int32_t d = (int32_t)(w & 0x3fffff);
	if (d & 0x200000) {
		d -= 0x400000;
	}
	uint32_t t = base + (uint32_t)d;
	return t < SCQ16_JD1_REACH ? 4 : leaf;
}

static int scq16_decode_second(const uint8_t *bytes, int len, int off, uint32_t addr, uint8_t nb, Scq16Insn *out) {
	/* B slot after a head of `off` bytes */
	uint8_t bop = bytes[off] & 0x7f, bv = bytes[off] >> 7;
	int LB;
	uint8_t bm[8];
	if (bv && bop >= 0x40 && bop <= 0x5f) {
		LB = 4;
	} else {
		LB = scq16_uleaf (bop, off + 1 < len ? bytes[off + 1] : 0);
	}
	if (LB <= 0) {
		return -1;
	}
	LB = scq16_jd1_len (bop, off + 1 < len ? bytes[off + 1] : 0, off + 2 < len ? bytes[off + 2] : 0, off + 3 < len ? bytes[off + 3] : 0, len - off, addr, LB);   /* j.d1 56 by target (base = packet start) */
	if (off + LB > len) {
		return scq16_need (out, off + LB);
	}
	memcpy (bm, bytes + off, LB);
	bm[0] = bop;
	scq16_decode_unit (&out->u[1], bm, LB, addr + off, addr, SCQ16_S_B);
	memcpy (out->u[1].raw, bytes + off, LB);
	out->u[1].nb = nb;
	out->n = 2;
	out->kind = SCQ16_I_PACKET;
	out->size = off + LB;
	return out->size;
}

int scq16_decode_insn(const uint8_t *bytes, int len, uint32_t addr, Scq16Insn *out) {
	memset (out, 0, sizeof (*out));
	out->addr = addr;
	if (len < 1) {
		return scq16_need (out, 2);
	}
	const uint8_t b0 = bytes[0];
	const uint8_t b1 = len > 1 ? bytes[1] : 0;
	uint8_t bm[8];
	int L, i;
	if (b0 < 0x80 || b0 >= 0xf8) {
		/* ---- stand-alone (00-7f) / masked orphan (f8-ff) */
		L = scq16_uleaf (b0 & 0x7f, b1);
		if (L <= 0) {
			return -1;
		}
		L = scq16_jd1_len (b0, b1, len > 2 ? bytes[2] : 0, len > 3 ? bytes[3] : 0, len, addr, L);   /* j.d1 56 by target */
		if (L > len) {
			return scq16_need (out, L);
		}
		memcpy (bm, bytes, L);
		bm[0] = b0 & 0x7f;
		scq16_decode_unit (&out->u[0], bm, L, addr, addr, b0 >= 0xf8 ? SCQ16_S_ORPHAN : SCQ16_S_UNIT);
		memcpy (out->u[0].raw, bytes, L);
		out->u[0].masked = b0 >= 0xf8;
		out->n = 1; out->kind = SCQ16_I_UNIT; out->size = L;
	} else if (b0 >= 0xc0 && b0 <= 0xdf) {
		/* ---- stand-alone 4-byte vector operation */
		if (len < 4) {
			return scq16_need (out, 4);
		}
		scq16_decode_unit_alt (&out->u[0], bytes, 4, addr, addr, SCQ16_S_UNIT, &scq16_alts[SCQ16_VEC_ALT]);
		memcpy (out->u[0].raw, bytes, 4);
		out->n = 1; out->kind = SCQ16_I_UNIT; out->size = 4;
	} else if (b0 >= 0xf0 && b0 <= 0xf7) {
		/* ---- 8-byte bundle */
		if (len < 8) {
			return scq16_need (out, 8);
		}
		scq16_decode_unit (&out->u[0], bytes, 8, addr, addr, SCQ16_S_UNIT);
		memcpy (out->u[0].raw, bytes, 8);
		uint64_t w = out->u[0].w;
		uint32_t s1 = (uint32_t)((w >> 15) & 0x7fff), s2 = (uint32_t)(w & 0x7fff);
		bm[0] = (s1 >> 8) & 0x7f; bm[1] = s1 & 0xff;
		scq16_decode_unit (&out->u[1], bm, 2, addr, addr, SCQ16_S_S1);
		memcpy (out->u[1].raw, bm, 2);
		bm[0] = (s2 >> 8) & 0x7f; bm[1] = s2 & 0xff;
		scq16_decode_unit (&out->u[2], bm, 2, addr, addr, SCQ16_S_S2);
		memcpy (out->u[2].raw, bm, 2);
		out->n = 3; out->kind = SCQ16_I_BUNDLE; out->size = 8;
	} else {
		/* ---- 80-bf scalar head / orphan, e0-ef vector head */
		int LA;
		if (b0 >= 0xe0) {
			LA = 4;
		} else {
			const uint8_t b2 = len > 2 ? bytes[2] : 0;
			const uint8_t a0 = (uint8_t)((b0 << 1) | (b1 >> 7)), a1 = (uint8_t)((b1 << 1) | (b2 >> 7));
			int lab = scq16_hleaf (a0, a1);
			if (lab == 0) {
				return -1;
			}
			if (lab < 0) {
				/* masked orphan: A' of control/system */
				L = -lab;
				if (L > len) {
					return scq16_need (out, L);
				}
				memcpy (bm, bytes, L);
				bm[0] = b0 & 0x7f;
				scq16_decode_unit (&out->u[0], bm, L, addr, addr, SCQ16_S_ORPHAN);
				memcpy (out->u[0].raw, bytes, L);
				out->u[0].masked = true;
				out->n = 1; out->kind = SCQ16_I_UNIT; out->size = L;
				goto done;
			}
			LA = lab;
		}
		if (LA > len) {
			return scq16_need (out, LA);
		}
		const uint8_t nb = LA < len ? (bytes[LA] >> 7) : 0;
		scq16_shift_bytes (bm, bytes, LA, nb);
		scq16_decode_unit_alt (&out->u[0], bm, LA, addr, addr, SCQ16_S_A, b0 >= 0xe0 ? &scq16_alts[SCQ16_VEC_ALT] : NULL);
		memcpy (out->u[0].raw, bytes, LA);
		out->u[0].nb = nb;
		out->n = 1; out->kind = SCQ16_I_UNIT; out->size = LA;
		if (LA >= len) {
			/* head without a visible B slot (the buffer ends): reported alone, with the suffix ! */
			out->u[0].last_head = true;
			return scq16_need (out, LA + 2);
		}
		if (scq16_decode_second (bytes, len, LA, addr, nb, out) <= 0) {
			return out->size;
		}
	}
done:
	for (i = 0; i < out->n; i++) {
		const Scq16Unit *u = &out->u[i];
		if (u->alt && u->alt->slots > out->delay && (u->alt->kind == SCQ16_K_JUMP || u->alt->kind == SCQ16_K_CALL || u->alt->kind == SCQ16_K_BRANCH || u->alt->kind == SCQ16_K_RET || u->alt->kind == SCQ16_K_LOOP)) {
			out->delay = u->alt->slots;
		}
	}
	return out->size;
}

/* ------------------------------------------------------------------------------------------------ text ----------- */
int scq16_operand_index(const Scq16Unit *u, const char *name) {
	int i;
	if (!u->alt) {
		return -1;
	}
	for (i = 0; i < u->alt->nops; i++) {
		if (!strcmp (u->alt->ops[i].name, name)) {
			return i;
		}
	}
	return -1;
}

static int scq16_sbcat(char *buf, size_t n, size_t *pos, const char *s) {
	size_t l = strlen (s);
	if (*pos + l + 1 > n) {
		l = n > *pos + 1 ? n - *pos - 1 : 0;
	}
	memcpy (buf + *pos, s, l);
	*pos += l;
	buf[*pos] = 0;
	return (int)l;
}

static void scq16_fmt_hex(char *o, size_t n, int64_t v, const char *prefix) {
	if (v < 0) {
		snprintf (o, n, "%s-0x%x", prefix, (unsigned)(-(int64_t)v));
	} else {
		snprintf (o, n, "%s0x%x", prefix, (unsigned)v);
	}
}

static void scq16_operand_text(const Scq16Unit *u, int i, char *o, size_t n, Scq16Symf sym, void *user) {
	const Scq16Operand *op = &u->alt->ops[i];
	int32_t v = u->vals[i];
	/* unsigned immediates print as uint32 (sethi #0xfff00000) */
	int64_t hv = (op->kind == SCQ16_O_IMM && !op->is_signed && op->bias >= 0) ? (int64_t)(uint32_t)v : (int64_t)v;
	switch (op->kind) {
	case SCQ16_O_R5: case SCQ16_O_R4: case SCQ16_O_R4P: case SCQ16_O_R3P:
		snprintf (o, n, "%s", scq16_regs[v & 31]);
		return;
	case SCQ16_O_CSR:
		snprintf (o, n, "%s", scq16_csrs[v & 31]);
		return;
	case SCQ16_O_ACC:
		snprintf (o, n, "%s", scq16_accs[v & 31]);
		return;
	case SCQ16_O_DISP:
		if (op->fmt == SCQ16_F_DISPX || !sym) {
			if (op->fmt == SCQ16_F_DISPX) {
				snprintf (o, n, "0x%x", (unsigned)v);
			} else {
				snprintf (o, n, "0x%08x", (unsigned)v);
			}
		} else {
			const char *s = sym (user, (uint32_t)v, o, n);
			if (s != o) {
				snprintf (o, n, "%s", s);
			}
		}
		return;
	default:
		break;
	}
	switch (op->fmt) {
	case SCQ16_F_D: snprintf (o, n, "#%d", v); break;
	case SCQ16_F_X: scq16_fmt_hex (o, n, hv, "#"); break;
	case SCQ16_F_XB: scq16_fmt_hex (o, n, hv, ""); break;
	case SCQ16_F_N: snprintf (o, n, "%d", v); break;
	case SCQ16_F_INC:
		if (v > -16 && v < 16) {
			snprintf (o, n, "%d", v);
		} else {
			scq16_fmt_hex (o, n, v, "");
		}
		break;
	case SCQ16_F_PM:
		if (v >= 0) {
			snprintf (o, n, "+= 0x%x", (unsigned)v);
		} else {
			snprintf (o, n, "-= 0x%x", (unsigned)(-(int64_t)v));
		}
		break;
	case SCQ16_F_H2: snprintf (o, n, "%02x", (unsigned)v); break;
	case SCQ16_F_HX: snprintf (o, n, "%x", (unsigned)v); break;
	case SCQ16_F_B3: snprintf (o, n, "%d%d%d", (v >> 2) & 1, (v >> 1) & 1, v & 1); break;
	case SCQ16_F_X04: snprintf (o, n, "0x%02x", (unsigned)v); break;
	case SCQ16_F_X05: snprintf (o, n, "0x%03x", (unsigned)v); break;
	case SCQ16_F_X06: snprintf (o, n, "0x%04x", (unsigned)v); break;
	default: snprintf (o, n, "%d", v); break;
	}
}


/* the vector name of the table (scq16_vname[op9]) carries the ? when the name is PROVISIONAL and none when it is an established
 * operation (v.move.mv, v.mem.ld, v.mem.st); the decoder adds no ? of its own. */
static bool scq16_vname_firm(const char *nm) {
	size_t l = nm ? strlen (nm) : 0;
	return l > 0 && nm[l - 1] != '?';
}

const char *scq16_unit_mnemonic(const Scq16Unit *u, char *buf, size_t n) {
	if (!u->alt) {
		const char *tag = u->slot == SCQ16_S_A ? ".p" : u->slot == SCQ16_S_B ? ".q" : u->slot == SCQ16_S_ORPHAN ? ".o" : (u->slot == SCQ16_S_S1 || u->slot == SCQ16_S_S2) ? ".s" : ".b";
		snprintf (buf, n, "%s%d%s", tag, u->L, u->last_head ? "!" : "");
		return buf;
	}
	if (u->alt == &scq16_alts[SCQ16_VEC_ALT] || u->alt == &scq16_alts[SCQ16_BUNDLE_ALT]) {
		const char *cls = scq16_vclass_names[scq16_vclass[u->op9]];
		const char *nm = scq16_vname[u->op9];
		if (u->alt == &scq16_alts[SCQ16_BUNDLE_ALT]) {
			snprintf (buf, n, "vbundle");
		} else if (nm) {
			snprintf (buf, n, "v.%s.%s%s", cls, nm, u->last_head ? "!" : "");
		} else {
			snprintf (buf, n, "v.%s%s", cls, u->last_head ? "!" : "");
		}
		return buf;
	}
	snprintf (buf, n, "%s%s%s", u->alt->mn, u->masked ? ".p" : "", u->last_head ? "!" : "");
	return buf;
}

int scq16_unit_operands(const Scq16Unit *u, char *buf, size_t n, Scq16Symf sym, void *user) {
	size_t pos = 0;
	buf[0] = 0;
	if (!u->alt) {
		int i;
		for (i = 0; i < u->L; i++) {
			char h[4];
			snprintf (h, sizeof (h), "%s%02x", i ? " " : "", u->b[i]);
			scq16_sbcat (buf, n, &pos, h);
		}
		return (int)pos;
	}
	const char *t = u->alt->fmt;
	while (*t) {
		if (*t == '{') {
			const char *e = strchr (t, '}');
			char name[16];
			size_t l = e ? (size_t)(e - t - 1) : 0;
			if (!e || l >= sizeof (name)) {
				scq16_sbcat (buf, n, &pos, "{");
				t++;
				continue;
			}
			memcpy (name, t + 1, l);
			name[l] = 0;
			int idx = scq16_operand_index (u, name);
			char o[48];
			if (idx >= 0) {
				scq16_operand_text (u, idx, o, sizeof (o), sym, user);
			} else {
				snprintf (o, sizeof (o), "{%s}", name);
			}
			scq16_sbcat (buf, n, &pos, o);
			t = e + 1;
		} else {
			char c[2] = { *t, 0 };
			scq16_sbcat (buf, n, &pos, c);
			t++;
		}
	}
	return (int)pos;
}

static const char *scq16_vec_operands(const Scq16Unit *u, char *o, size_t n) {
	uint32_t v = u->vec32;
	snprintf (o, n, "op9=0x%03x A%u B%u F%u,F%u,F%u", v & 0x1ff, (v >> 26) & 7, (v >> 24) & 3, (v >> 19) & 31, (v >> 14) & 31, (v >> 9) & 31);
	return o;
}

int scq16_unit_text(const Scq16Unit *u, char *buf, size_t n, Scq16Symf sym, void *user) {
	char mn[32], ops[160];
	scq16_unit_mnemonic (u, mn, sizeof (mn));
	if (u->alt == &scq16_alts[SCQ16_VEC_ALT] || u->alt == &scq16_alts[SCQ16_BUNDLE_ALT]) {
		scq16_vec_operands (u, ops, sizeof (ops));
	} else {
		scq16_unit_operands (u, ops, sizeof (ops), sym, user);
	}
	if (ops[0]) {
		return snprintf (buf, n, "%-9s %s", mn, ops);
	}
	return snprintf (buf, n, "%s", mn);
}

int scq16_insn_text(const Scq16Insn *in, char *buf, size_t n, Scq16Symf sym, void *user) {
	char a[256], b[256], c[256];
	if (in->kind == SCQ16_I_BUNDLE) {
		char mn[32], vo[96];
		const Scq16Unit *v = &in->u[0];
		const char *cls = scq16_vclass_names[scq16_vclass[v->op9]];
		const char *nm = scq16_vname[v->op9];
		if (nm) {
			snprintf (mn, sizeof (mn), "v.%s.%s", cls, nm);
		} else {
			snprintf (mn, sizeof (mn), "v.%s", cls);
		}
		scq16_vec_operands (v, vo, sizeof (vo));
		/* the slots print as "mn ops" with a single space */
		char m1[32], o1[160], m2[32], o2[160];
		scq16_unit_mnemonic (&in->u[1], m1, sizeof (m1)); scq16_unit_operands (&in->u[1], o1, sizeof (o1), sym, user);
		scq16_unit_mnemonic (&in->u[2], m2, sizeof (m2)); scq16_unit_operands (&in->u[2], o2, sizeof (o2), sym, user);
		if (!in->u[1].alt) { snprintf (m1, sizeof (m1), ".s2"); }
		if (!in->u[2].alt) { snprintf (m2, sizeof (m2), ".s2"); }
		snprintf (a, sizeof (a), "%s%s%s", m1, o1[0] ? " " : "", o1);
		snprintf (b, sizeof (b), "%s%s%s", m2, o2[0] ? " " : "", o2);
		return snprintf (buf, n, "vbundle   %s %s \xe2\x80\x96 %s \xe2\x80\x96 %s", mn, vo, a, b);
	}
	scq16_unit_text (&in->u[0], a, sizeof (a), sym, user);
	if (in->kind == SCQ16_I_PACKET) {
		scq16_unit_text (&in->u[1], c, sizeof (c), sym, user);
		return snprintf (buf, n, "{ %s \xe2\x80\x96 %s }", a, c);
	}
	return snprintf (buf, n, "%s", a);
}

/* ------------------------------------------------------------------------------------------------ VU registers ---- */
/* scalar state of the VU exposed as ESIL registers: vu0-31 (vget), v0-31 (scalar shadow of vbcast),
 * va0-7 (vset.a), vp0-7 (vmem.set), vs0-15 (vins?), vb1_/vb3_/vb5_ 0-31 (vrd?/vwr?), udf0-31 (the udf port) */
static const char *const scq16_vu_prefix[] = { "vu", "v", "va", "vp", "vs", "vb1_", "vb3_", "vb5_", "udf" };
static const int scq16_vu_count[] = { 32, 32, 8, 8, 16, 32, 32, 32, 32 };
#define SCQ16_NVU_PREFIX 9
static char scq16_vu_names[SCQ16_NVU_PREFIX][32][8];
static int scq16_vu_ready = 0;

static void scq16_vu_init(void) {
	int p, k;
	if (scq16_vu_ready) {
		return;
	}
	for (p = 0; p < SCQ16_NVU_PREFIX; p++) {
		for (k = 0; k < scq16_vu_count[p]; k++) {
			snprintf (scq16_vu_names[p][k], sizeof (scq16_vu_names[p][k]), "%s%d", scq16_vu_prefix[p], k);
		}
	}
	scq16_vu_ready = 1;
}

/* stable pointer to the name when s is a VU register, else NULL */
const char *scq16_vu_reg(const char *s) {
	int p, k;
	scq16_vu_init ();
	for (p = 0; p < SCQ16_NVU_PREFIX; p++) {
		size_t l = strlen (scq16_vu_prefix[p]);
		if (strncmp (s, scq16_vu_prefix[p], l) || s[l] < '0' || s[l] > '9') {
			continue;
		}
		k = atoi (s + l);
		if (k < 0 || k >= scq16_vu_count[p] || strcmp (s, scq16_vu_names[p][k])) {
			continue;
		}
		return scq16_vu_names[p][k];
	}
	return NULL;
}

/* total number of VU registers and the i-th name (register profile of the plugin) */
int scq16_vu_nregs(void) {
	int p, n = 0;
	for (p = 0; p < SCQ16_NVU_PREFIX; p++) {
		n += scq16_vu_count[p];
	}
	return n;
}

const char *scq16_vu_name(int i) {
	int p;
	scq16_vu_init ();
	for (p = 0; p < SCQ16_NVU_PREFIX; p++) {
		if (i < scq16_vu_count[p]) {
			return scq16_vu_names[p][i];
		}
		i -= scq16_vu_count[p];
	}
	return NULL;
}

/* ------------------------------------------------------------------------------------------------ ESIL ----------- */
static const char *scq16_reg_name_of(const Scq16Unit *u, int i) {
	const Scq16Operand *op = &u->alt->ops[i];
	switch (op->kind) {
	case SCQ16_O_R5: case SCQ16_O_R4: case SCQ16_O_R4P: case SCQ16_O_R3P: return scq16_regs[u->vals[i] & 31];
	case SCQ16_O_CSR: return scq16_csrs[u->vals[i] & 31];
	case SCQ16_O_ACC: return scq16_accs[u->vals[i] & 31];
	default: return NULL;
	}
}

static const char *scq16_remapped(const char *reg, const char *const (*remap)[2], int nremap) {
	int i;
	for (i = 0; i < nremap; i++) {
		if (!strcmp (remap[i][0], reg)) {
			return remap[i][1];
		}
	}
	return reg;
}

/* expand a reference {name} / {=name} / {#name} / {d} / {ret} / {mask} into o (returns false when the operand does not exist) */
static bool scq16_esil_ref(const Scq16Unit *u, const char *nm_in, size_t nl, uint32_t ret, const char *const (*remap)[2], int nremap, char *o, size_t on) {
	char nm[32];
	bool wr = false, dec = false;
	const char *name = nm_in;
	if (name[0] == '=') {
		wr = true;
		name++;
		nl--;
	} else if (name[0] == '#') {
		dec = true;
		name++;
		nl--;
	}
	if (nl >= sizeof (nm)) {
		nl = sizeof (nm) - 1;
	}
	memcpy (nm, name, nl);
	nm[nl] = 0;
	if (!strcmp (nm, "d")) {
		snprintf (o, on, "0x%x", (unsigned)u->target);
	} else if (!strcmp (nm, "ret")) {
		snprintf (o, on, "0x%x", (unsigned)ret);
	} else if (!strcmp (nm, "mask")) {
		int wi = scq16_operand_index (u, "wd");
		uint32_t wd = wi >= 0 ? (uint32_t)u->vals[wi] : 32;
		snprintf (o, on, "0x%x", (unsigned)(wd >= 32 ? 0xffffffffu : ((1u << wd) - 1)));
	} else {
		int idx = scq16_operand_index (u, nm);
		if (idx < 0) {
			return false;
		}
		const char *reg = scq16_reg_name_of (u, idx);
		if (dec) {
			/* {#op}: decimal value (ESIL register names of the VU: vu{#k}, vb5_{#k}...) */
			snprintf (o, on, "%d", (int)u->vals[idx]);
		} else if (reg) {
			snprintf (o, on, "%s", wr ? reg : scq16_remapped (reg, remap, nremap));
		} else if (u->alt->ops[idx].kind == SCQ16_O_DISP) {
			snprintf (o, on, "0x%x", (unsigned)u->vals[idx]);
		} else {
			snprintf (o, on, "0x%x", (unsigned)(uint32_t)u->vals[idx]);
		}
	}
	return true;
}

/* hook that substitutes the ESIL template of an alternative (experiments); NULL = the table */
const char *(*scq16_esil_override)(const Scq16Alt *a) = NULL;

int scq16_unit_esil(const Scq16Unit *u, char *buf, size_t n, uint32_t ret, const char *const (*remap)[2], int nremap) {
	size_t pos = 0;
	buf[0] = 0;
	if (!u->alt) {
		return -1;
	}
	const char *t = scq16_esil_override ? scq16_esil_override (u->alt) : NULL;
	if (!t) {
		t = u->alt->esil;
	}
	if (!t) {
		return -1;
	}
	/* literal tokens (sp, lr, pc, a0l, a0h, ipc) are remapped too when they are reads: a register token followed by "=" is
	 * a write; "=[n]" uses the previous token as the address (a read).  A reference {..} may sit inside a token
	 * (vu{#k}: a VU register with a decimal index). */
	while (*t) {
		const char *e = strchr (t, ',');
		size_t l = e ? (size_t)(e - t) : strlen (t);
		char tok[64];
		if (l >= sizeof (tok)) {
			l = sizeof (tok) - 1;
		}
		memcpy (tok, t, l);
		tok[l] = 0;
		const char *next = e ? e + 1 : "";
		bool is_write = next[0] == '=' && (next[1] == ',' || next[1] == 0);
		char o[96];
		if (strchr (tok, '{') && strchr (tok, '}') && tok[0] != '?' && tok[0] != '}') {
			/* expand every reference {..} of the token (the control tokens ?{ }{ } pass through literally) */
			char out[96] = "";
			size_t op = 0;
			const char *p = tok;
			while (*p) {
				if (*p == '{') {
					const char *q = strchr (p, '}');
					char ref[72];
					if (!q) {
						return -1;
					}
					if (!scq16_esil_ref (u, p + 1, (size_t)(q - p - 1), ret, remap, nremap, ref, sizeof (ref))) {
						return -1;
					}
					size_t rl = strlen (ref);
					if (op + rl >= sizeof (out)) {
						return -1;
					}
					memcpy (out + op, ref, rl);
					op += rl;
					out[op] = 0;
					p = q + 1;
				} else {
					if (op + 1 >= sizeof (out)) {
						return -1;
					}
					out[op++] = *p++;
					out[op] = 0;
				}
			}
			/* a VU register read inside a packet is remapped too */
			const char *vu = scq16_vu_reg (out);
			if (vu && !is_write) {
				snprintf (o, sizeof (o), "%s", scq16_remapped (vu, remap, nremap));
			} else {
				snprintf (o, sizeof (o), "%s", out);
			}
		} else if (!is_write && (!strcmp (tok, "sp") || !strcmp (tok, "lr") || !strcmp (tok, "pc") || !strcmp (tok, "a0l") || !strcmp (tok, "a0h") || !strcmp (tok, "ipc"))) {
			snprintf (o, sizeof (o), "%s", scq16_remapped (tok, remap, nremap));
		} else {
			snprintf (o, sizeof (o), "%s", tok);
		}
		/* the ESIL machine of radare2 computes in 64 bits and `aes` does not mask the address of a memory access: a negative frame
		 * offset over a 32-bit base would wrap above 4 GB (read-err); the address of every [n] / =[n] is cut to 32 bits */
		if ((o[0] == '[' || (o[0] == '=' && o[1] == '[')) && strchr (o, ']')) {
			scq16_sbcat (buf, n, &pos, "0xffffffff,&,");
		}
		scq16_sbcat (buf, n, &pos, o);
		if (e) {
			scq16_sbcat (buf, n, &pos, ",");
			t = e + 1;
		} else {
			break;
		}
	}
	return (int)pos;
}

int scq16_unit_esil_regs(const Scq16Unit *u, uint32_t ret, bool written, const char **out, int max) {
	char esil[512];
	int cnt = 0;
	if (scq16_unit_esil (u, esil, sizeof (esil), ret, NULL, 0) < 0) {
		return 0;
	}
	char *s = esil;
	while (*s) {
		char *e = strchr (s, ',');
		if (e) {
			*e = 0;
		}
		const char *next = e ? e + 1 : "";
		bool is_write = next[0] == '=' && (next[1] == ',' || next[1] == 0);
		bool is_reg = (s[0] == 'r' && s[1] >= '0' && s[1] <= '9') || !strcmp (s, "sp") || !strcmp (s, "lr") || !strcmp (s, "a0l") || !strcmp (s, "a0h")
			|| !strcmp (s, "ipc") || !strcmp (s, "sr") || !strcmp (s, "isr") || !strcmp (s, "lf") || (s[0] == 'l' && (s[1] == 's' || s[1] == 'e' || s[1] == 'c') && s[2] >= '0' && s[2] <= '2' && !s[3]) || !strncmp (s, "csr", 3)
			|| scq16_vu_reg (s) != NULL;
		if (is_reg && is_write == written && cnt < max) {
			int k, dup = 0;
			for (k = 0; k < cnt; k++) {
				if (!strcmp (out[k], s)) {
					dup = 1;
				}
			}
			if (!dup) {
				/* return stable pointers: look the name up in the tables */
				const char *stable = NULL;
				int r;
				for (r = 0; r < 32 && !stable; r++) {
					if (!strcmp (scq16_regs[r], s)) {
						stable = scq16_regs[r];
					}
				}
				for (r = 0; r < 32 && !stable; r++) {
					if (!strcmp (scq16_csrs[r], s)) {
						stable = scq16_csrs[r];
					}
				}
				for (r = 0; r < 32 && !stable; r++) {
					if (!strcmp (scq16_accs[r], s)) {
						stable = scq16_accs[r];
					}
				}
				if (!stable) {
					stable = scq16_vu_reg (s);
				}
				if (stable) {
					out[cnt++] = stable;
				}
			}
		}
		if (!e) {
			break;
		}
		s = e + 1;
	}
	return cnt;
}
