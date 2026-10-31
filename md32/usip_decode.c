/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* uSIP packet decoder: a table-driven reading of VLIW packets (parse_group, group_parses, decode_asg, score, fviol,
 * parse_packet) over the generated form table usip_opcodes.h.  The reading chosen for a packet is deterministic and prior-free: among the consistent readings
 * (every group split and head/tail assignment the table allows, plus the explicit candidates of the packet grammar)
 * the smallest (s0, I, Fv, -A, K) wins: s0 = unknown units + the documented tie-break penalties, I = number of
 * instructions, Fv = heads with a tail whose adjacency contradicts the F pattern, A = adjacent tails, K = the
 * lexicographic key of the assignment.  The 48/64-bit b<cond>.l prefix forms are matched on the first units of the
 * packet before the layout.  The only outside knowledge is what the caller passes in UsipGuardCtx (packet starts of
 * the function being decoded, function starts) for the forms that carry a target guard. */

#include <r_util.h>
#include "usip_opcodes.h"
#include "usip_decode.h"

#define N_OPS ((int)(sizeof (usip_opcodes) / sizeof (usip_opcodes[0])))
#define NU USIP_MAX_UNITS
#define ASG_HARD_CAP 20000     /* generous bound; guards pathological input */
#define GROUP_PARSES_LIMIT 96  /* group_parses stops enumerating splits past this many readings */

/* scores are quarter units: 0.25 -> 1 */
#define Q(x) ((int)((x) * 4))

/* ---------------------------------------------------------------------------------------------------- tables */

const char *usip_kind_name(int kind) {
	return (kind >= 0 && kind < (int)R_ARRAY_SIZE (usip_kind_names))? usip_kind_names[kind]: "?";
}

const char *usip_conf_name(int conf) {
	static const char *const names[] = { "high", "medium", "low", "format-only" };
	return (conf >= 0 && conf < 4)? names[conf]: "?";
}

int usip_op_index(const UsipOpcode *op) {
	return op? (int)(op - usip_opcodes): -1;
}

const char *usip_op_form(const UsipOpcode *op) {
	return op? op->form: NULL;
}

int usip_op_kind(const UsipOpcode *op) {
	return op? op->kind: USIP_K_OTHER;
}

int usip_op_conf(const UsipOpcode *op) {
	return op? op->conf: USIP_CONF_FORMAT;
}

unsigned usip_op_flags(const UsipOpcode *op) {
	return op? op->flags: 0;
}

int usip_op_nargs(const UsipOpcode *op) {
	return op? op->nargs: 0;
}

const char *usip_op_field_name(const UsipOpcode *op, int i) {
	return (op && i >= 0 && i < op->nfields)? op->fields[i].name: NULL;
}

int usip_op_field_type(const UsipOpcode *op, int i) {
	return (op && i >= 0 && i < op->nfields)? op->fields[i].type: -1;
}

const char *usip_csr_ext_name(int csr) {
	return (csr >= 0 && csr < 64)? usip_csr_ext[csr]: NULL;
}

/* ---------------------------------------------------------------------------------------------------- fields */

static st64 sext(ut64 v, int n) {
	if (n <= 0 || n >= 64) {
		return (st64)v;
	}
	const ut64 m = 1ULL << (n - 1);
	v &= (1ULL << n) - 1;
	return (st64)((v ^ m) - m);
}

static st64 field_value(const UsipOpcode *op, int fi, ut64 w) {
	const UsipField *f = &op->fields[fi];
	ut64 raw = 0;
	int nb = 0, i;
	for (i = 0; i < f->nranges; i++) {
		const UsipBits *r = &f->r[i];
		if (r->hi == 0xff) {
			raw <<= r->lo;
			nb += r->lo;
		} else {
			const int width = r->hi - r->lo + 1;
			raw = (raw << width) | ((w >> r->lo) & ((1ULL << width) - 1));
			nb += width;
		}
	}
	const int sc = f->scale? f->scale: 1;
	switch (f->type) {
	case USIP_A_MOVHI:
		/* the collected bits (V20 of movhi, f12 >> 1 of the small cell) << 12 */
		return (st64)((raw << 12) & UT32_MAX);
	case USIP_A_OFFH:
		/* half-word offset: odd f12 = f12 - 0x1001 (negative) */
		return (raw & 1)? (st64)raw - 0x1001: (st64)raw;
	case USIP_A_OFFW:
		/* word offset: f12 = 3 mod 4 >= 0x800 is a negative multiple of 4 */
		return ((raw & 3) == 3 && raw >= 0x800)? 4 * sext (raw >> 2, 10): (st64)raw;
	case USIP_A_LOOPN:
		/* loop #N over rrr:x:B */
		return (st64)((raw >> 1) + ((raw & 0x1F)? 1: 0));
	case USIP_A_SIMM:
		return sext (raw, nb) * sc;
	case USIP_A_DISP:
		return sext (raw, nb) * sc + (st32)f->base;
	case USIP_A_ROTIMM: {
		const int n = f->nbits? f->nbits: nb;
		const ut64 r = ((raw >> 1) | ((raw & 1) << (n - 1))) & ((1ULL << n) - 1);
		return sext (r, n);
	}
	case USIP_A_UROT: {
		const int n = f->nbits? f->nbits: nb;
		return (st64)(((raw >> 1) | ((raw & 1) << (n - 1))) & ((1ULL << n) - 1));
	}
	case USIP_A_ABSADDR:
		return (st64)(f->base | raw);
	case USIP_A_ACC:
		return (st64)(raw & 3);
	default:
		/* reg, imm, flag, csr, csr_ext, accw, udisp: scaled, plus the constant of the field (rB + 1, m + 1) */
		return (st64)(raw * (ut64)sc) + (st32)f->base;
	}
}

static inline bool is_hi1010(ut32 u) {
	return (u >> 15) == 0 && ((u >> 9) & 0xF) == 0xA;
}

static inline bool is_osyl(ut16 u) {
	return ((u >> 11) & 7) == 7;
}

/* ret / save / restore never take tails */
static inline bool never_tail(ut16 h) {
	return (h & 0x3FFF) == 0x1EF9 || (h & 0x3F0F) == 0x1F05;
}

/* head of the 48-bit family [0][F][01][A][B][op in {0,4,5,6,7}]: never a hi(1010) nor ret/save/restore */
static bool fam_head(ut16 v) {
	const int op = v & 0xF;
	return (v >> 15) == 0 && ((v >> 12) & 3) == 1 && (op == 0 || (op >= 4 && op <= 7)) && !is_hi1010 (v) && !never_tail (v);
}

/* ---------------------------------------------------------------------------------------------------- form info */

enum { TG_NONE = 0, TG_PK, TG_FN, TG_FN_OR_PK };
#define FI_TG_MASK 0x03   /* target-guard kind (TG_*) */
#define FI_BS      0x04   /* guard head_not_validated_bs */
#define FI_DEFER   0x08   /* has deferred (position / packet-length / context) constraints */
#define FI_DONE    0x80

static bool cons_deferred(int op) {
	switch (op) {
	case USIP_C_PACKET_LEN: case USIP_C_PACKET_LEN_GE: case USIP_C_HEAD_INDEX: case USIP_C_HEAD_INDEX_GE: case USIP_C_CTX:
		return true;
	}
	return false;
}

static bool cons_is_guard(int op) {
	switch (op) {
	case USIP_C_GUARD_TARGET_PACKET_START: case USIP_C_GUARD_TARGET_FUNCTION_START:
	case USIP_C_GUARD_TARGET_FN_OR_PACKET_START: case USIP_C_GUARD_HEAD_NOT_VALIDATED_BS:
		return true;
	}
	return false;
}

/* per-form summary of the constraint classes (computed once) */
static ut8 finfo[sizeof (usip_opcodes) / sizeof (usip_opcodes[0])];
static ut64 mfcsr_known;   /* CSR numbers of the canonical mfcsr pair (the `in` set of the mfcsr form) */

static void finfo_init(void) {
	int i, j;
	if (finfo[0] & FI_DONE) {
		return;
	}
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		ut8 v = 0;
		for (j = 0; j < f->ncons; j++) {
			switch (f->cons[j].op) {
			case USIP_C_GUARD_TARGET_PACKET_START: v |= TG_PK; break;
			case USIP_C_GUARD_TARGET_FUNCTION_START: v |= TG_FN; break;
			case USIP_C_GUARD_TARGET_FN_OR_PACKET_START: v |= TG_FN_OR_PK; break;
			case USIP_C_GUARD_HEAD_NOT_VALIDATED_BS: v |= FI_BS; break;
			default:
				if (cons_deferred (f->cons[j].op)) {
					v |= FI_DEFER;
				}
				break;
			}
		}
		finfo[i] = v;
		if (!strcmp (f->form, "mfcsr") && f->ncons) {
			const UsipCons *c = &f->cons[0];
			if (c->op == USIP_C_INMASK) {
				mfcsr_known = (ut32)c->vals[0] | ((ut64)(ut32)c->vals[1] << 32);
			} else if (c->op == USIP_C_IN) {
				for (j = 0; j < c->nvals; j++) {
					if (c->vals[j] >= 0 && c->vals[j] < 64) {
						mfcsr_known |= 1ULL << c->vals[j];
					}
				}
			}
		}
	}
	finfo[0] |= FI_DONE;
}

static inline int tguard(const UsipOpcode *op) {
	return finfo[op - usip_opcodes] & FI_TG_MASK;
}

static inline ut8 form_info(const UsipOpcode *op) {
	return finfo[op - usip_opcodes];
}

/* ---------------------------------------------------------------------------------------------------- target guards */

/* Guarded forms that may be read UNVERIFIED when the guard cannot be evaluated (the function table is absent, or the
 * forward target lies beyond the bytes the caller could see).  Measured on the sample the table was built from
 * (doc/usip.md): the unverified readings of these forms are right in nearly every case where they compete (call with
 * the F' = 0 tail at +2, b with the F' = 0 tail, compare-and-branch with immediate and the F' = 0 tail, beqz.d, the
 * b<cond>.l prefix forms with a forward target, loop #N with F = S = 1, with F = 0 and the tail adjacent, and with F = 1
 * and the S = 0 tail at +2).  The other guarded forms are NOT accepted unverified: bnez.d (the cell is shared with the
 * op C DSP pairs), the register compare-and-branch with the F' = 0 tail (shared with .ctl15), loop rX with the F' = 0
 * tail (movi || mov pairs), loop #N with F = 0 and the tail at +2, far b and the 16-bit call.s with bit 15 = 0 (only a
 * small fraction of the shapes are calls). */
static bool unverified_ok(const UsipOpcode *op, int dist) {
	static const char *const forms[] = {
		"call_F0", "b_F0", "beqz_d",
		"beq_imm8_F0", "bne_imm8_F0", "ble_imm8_F0", "blt_imm8_F0", "bgtu_imm8_F0", "bge_imm8_F0", "bgt_imm8_F0",
		"loop_imm_F1S1", "loop_imm_F1S0",
	};
	size_t i;
	if (op->flags & USIP_F_PREFIX) {
		return true;
	}
	if (!strcmp (op->form, "loop_imm_F0S0")) {
		return dist == 1;
	}
	for (i = 0; i < R_ARRAY_SIZE (forms); i++) {
		if (!strcmp (op->form, forms[i])) {
			return true;
		}
	}
	return false;
}

/* USIP_G_OK / USIP_G_UNVERIFIED when the form may be read, 0 when the pair is data (16-bit: falls through; prefix
 * forms: not taken); dist = distance of the tail (0 when not applicable) */
static int eval_tguard(const UsipGuardCtx *g, const UsipOpcode *op, int tg, ut64 target, int dist) {
	int pk = -1, fn = -1;
	if (tg == TG_PK || tg == TG_FN_OR_PK) {
		pk = (g && g->packet_start)? g->packet_start (g->user, target): -1;
		if (pk == 1) {
			return USIP_G_OK;
		}
		if (tg == TG_PK) {
			return (pk < 0 && unverified_ok (op, dist))? USIP_G_UNVERIFIED: 0;
		}
	}
	fn = (g && g->function_start)? g->function_start (g->user, target): -1;
	if (fn == 1) {
		return USIP_G_OK;
	}
	if (fn == 0) {
		return 0;
	}
	if (tg == TG_FN_OR_PK) {
		return (pk < 0 && unverified_ok (op, dist))? USIP_G_UNVERIFIED: 0;
	}
	return unverified_ok (op, dist)? USIP_G_UNVERIFIED: 0;
}

/* R-st1h guard: a 16-bit b.s with bit 15 = 0 (5cX1/7cX1 = [0][1][m][1][110][x][B][0001], not m = 0 with d6 = 0) whose
 * target is a packet start of the same function */
static bool bs_valid(const UsipGuardCtx *g, ut64 pc, ut16 v) {
	if ((v & 0xDE0F) != 0x5C01) {
		return false;
	}
	const int m = (v >> 13) & 1, d6 = (v >> 3) & 0x3F;
	if (m == 0 && d6 == 0) {
		return false;
	}
	const ut64 tg = (pc + (m? 2 * (st64)(d6 - 64): 2 * (st64)d6)) & UT32_MAX;
	return g && g->packet_start && g->packet_start (g->user, tg) == 1;
}

/* ---------------------------------------------------------------------------------------------------- constraints */

/* context of the deferred constraints (position inside the packet, packet length, the other units) */
typedef struct {
	int pktlen;          /* units of this parse (-1 = unknown) */
	int k;               /* unit index of the head inside the packet (-1 = unknown) */
	const ut16 *units;   /* units of this parse (NULL = unknown) */
	int i;               /* index of the head in units */
} CtxD;

#define CM_FREE  1   /* context-free constraints */
#define CM_DEFER 2   /* deferred constraints (packet_len, head_index, ctx) */

static int match16_plain_idx(ut16 u, bool first, int pktlen, int k);

/* is the unit a named 16-bit op (in tail position if tail)?  Format-only shapes count, loose syllables and the
 * stand-alone closer forms do not (the packet length is unknown here, so their packet_len constraint fails). */
static bool known16(ut16 u, bool tail) {
	const int i = match16_plain_idx (u | 0x8000, !tail, -1, -1);
	const UsipOpcode *f = i < 0? NULL: &usip_opcodes[i];
	return f && f->kind != USIP_K_OTHER && !(f->flags & USIP_F_UNKNOWN16);
}

static bool any_sub(int op, st64 v, st64 val) {
	switch (op) {
	case USIP_ANY_EQ: return v == val;
	case USIP_ANY_NE: return v != val;
	case USIP_ANY_LT: return v < val;
	case USIP_ANY_GE: return v >= val;
	case USIP_ANY_GT: return v > val;
	case USIP_ANY_INMASK: return v >= 0 && v < 31 && (((ut32)val >> v) & 1);
	case USIP_ANY_NOTINMASK: return !(v >= 0 && v < 31 && (((ut32)val >> v) & 1));
	}
	return false;
}

/* the constraints of the classes in `which` hold for w; force_hi ignores the not_hi1010 shape of the head (the forced
 * decode of the H H T T candidate); the target guards and the b.s guard are never evaluated here */
static bool cons_ok(const UsipOpcode *op, ut64 w, bool first, const CtxD *ctxd, int which, bool force_hi) {
	int i, j;
	for (i = 0; i < op->ncons; i++) {
		const UsipCons *c = &op->cons[i];
		if (cons_is_guard (c->op) || !(which & (cons_deferred (c->op)? CM_DEFER: CM_FREE))) {
			continue;
		}
		if (force_hi && c->op == USIP_C_NOT_HI1010) {
			continue;
		}
		const st64 v = c->field != USIP_NOFIELD? field_value (op, c->field, w): 0;
		const ut16 t = w & 0xFFFF;
		bool ok = true;
		switch (c->op) {
		case USIP_C_EQ: ok = v == c->vals[0]; break;
		case USIP_C_NE: ok = v != c->vals[0]; break;
		case USIP_C_LT: ok = v < c->vals[0]; break;
		case USIP_C_GE: ok = v >= c->vals[0]; break;
		case USIP_C_GT: ok = v > c->vals[0]; break;
		case USIP_C_IN:
			ok = false;
			for (j = 0; j < c->nvals; j++) {
				ok |= v == c->vals[j];
			}
			break;
		case USIP_C_NOTIN:
			for (j = 0; j < c->nvals; j++) {
				ok &= v != c->vals[j];
			}
			break;
		case USIP_C_INMASK:
		case USIP_C_NOTINMASK: {
			const ut64 m = (ut32)c->vals[0] | ((ut64)(ut32)c->vals[1] << 32);
			const bool in = v >= 0 && v < 64 && ((m >> v) & 1);
			ok = c->op == USIP_C_INMASK? in: !in;
			break;
		}
		case USIP_C_RANGE: ok = v >= c->vals[0] && v < c->vals[1]; break;
		case USIP_C_RANGES:
			ok = false;
			for (j = 0; j + 1 < c->nvals; j += 2) {
				ok |= v >= c->vals[j] && v < c->vals[j + 1];
			}
			break;
		case USIP_C_EVEN: ok = (v & 1) == 0; break;
		case USIP_C_ODD: ok = (v & 1) == 1; break;
		case USIP_C_NOT_HI1010: ok = !is_hi1010 ((ut32)v); break;
		case USIP_C_EQ_FIELDS: ok = v == field_value (op, c->field2, w); break;
		case USIP_C_NE_FIELDS: ok = v != field_value (op, c->field2, w); break;
		case USIP_C_PACKET_LEN: ok = ctxd && ctxd->pktlen == c->vals[0]; break;
		case USIP_C_PACKET_LEN_GE: ok = ctxd && ctxd->pktlen >= 0 && ctxd->pktlen >= c->vals[0]; break;
		case USIP_C_HEAD_INDEX: ok = ctxd && ctxd->k == c->vals[0]; break;
		case USIP_C_HEAD_INDEX_GE: ok = ctxd && ctxd->k >= 0 && ctxd->k >= c->vals[0]; break;
		case USIP_C_CTX:
			/* unknown context: accept */
			if (ctxd && ctxd->units && c->vals[0] == USIP_CTX_NOT_EXT_OF_OP67) {
				/* a head at unit 1 with its low byte = 0 after a unit 0 with bit 15 = 0, F = 0 and op 6/7 is the extension
				 * word of that head */
				const ut16 h = (w >> (op->width - 16)) & 0xFFFF, u0 = ctxd->units[0];
				ok = !(ctxd->i == 1 && (h & 0xFF) == 0 && (u0 >> 15) == 0 && ((u0 & 0xF) == 6 || (u0 & 0xF) == 7) && ((u0 >> 14) & 1) == 0);
			}
			break;
		case USIP_C_SLOT0_EXCLUDES_HEAD: {
			const ut16 h = (w >> (op->width - 16)) & 0xFFFF;
			ok = !(first && (h & (ut16)c->vals[0]) == (ut16)c->vals[1]);
			break;
		}
		case USIP_C_ANY:
			ok = false;
			for (j = 0; j + 2 < c->nvals; j += 3) {
				ok |= any_sub (c->vals[j + 1], field_value (op, c->vals[j], w), c->vals[j + 2]);
			}
			break;
		case USIP_C_GUARD_SETCC_TAIL:
			ok = !known16 (t, true);
			for (j = 0; !ok && j < c->nvals; j++) {
				ok = (t & 0xFFF) == c->vals[j];
			}
			break;
		case USIP_C_GUARD_TAIL_NOT_NAMED16: ok = !known16 (t, true); break;
		case USIP_C_GUARD_OR2_TAIL: {
			const ut64 u12 = (ut64)v;
			const bool onebit = u12 != 0 && (u12 & (u12 - 1)) == 0;
			if (!known16 (t, true)) {
				ok = onebit || u12 < 0x100;
			} else {
				const ut16 h = (w >> 16) & 0xFFFF;
				ok = onebit && !known16 (h | 0x8000, true);
			}
			break;
		}
		default: break;
		}
		if (!ok) {
			return false;
		}
	}
	return true;
}

/* ---------------------------------------------------------------------------------------------------- 16-bit matching */

/* first matching 16-bit form WITHOUT a target guard (context-only forms excluded); cached per (packet length class,
 * head index class, slot, unit).  The 16-bit packet_len constraints only test 1, 2 and >= 2, the head_index ones 0 and
 * >= 2 (checked by the generator), hence the classes. */
static ut16 k16cache[4][3][2][0x10000];   /* 0 = unknown, 0xffff = none, else index + 1 */

static inline int pl_class(int pktlen) {
	return pktlen < 0? 0: pktlen == 1? 1: pktlen == 2? 2: 3;
}

static inline int k_class(int k) {
	return k == 0? 0: k >= 2? 2: 1;
}

static int match16_plain_idx(ut16 u, bool first, int pktlen, int k) {
	ut16 *slot = &k16cache[pl_class (pktlen)][k_class (k)][first? 1: 0][u];
	if (*slot) {
		return *slot == 0xffff? -1: *slot - 1;
	}
	const CtxD ctxd = { pktlen, k, NULL, 0 };
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 1 || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)
			|| ((f->flags & USIP_F_NOTSLOT0) && first) || (u & f->mask) != f->value || tguard (f)) {
			continue;
		}
		if (f->ncons && !cons_ok (f, u, first, &ctxd, CM_FREE | CM_DEFER, false)) {
			continue;
		}
		*slot = i + 1;
		return i;
	}
	*slot = 0xffff;
	return -1;
}

/* 16-bit forms with a target guard (call.s with bit 15 = 0), in table order */
static int guarded16[8];
static int n_guarded16 = -1;

static ut64 target_value(const UsipOpcode *f, ut64 w, ut64 pc, bool *has);

/* first matching 16-bit form: a guarded form that precedes the plain match is taken when its guard validates */
static const UsipOpcode *match16(const UsipGuardCtx *g, ut16 u, bool first, int pktlen, int k, ut64 pc, ut8 *guard) {
	const int ip = match16_plain_idx (u, first, pktlen, k);
	const int lim = ip < 0? N_OPS: ip;
	const CtxD ctxd = { pktlen, k, NULL, 0 };
	int i;
	*guard = USIP_G_NONE;
	if (n_guarded16 < 0) {
		n_guarded16 = 0;
		for (i = 0; i < N_OPS; i++) {
			const UsipOpcode *f = &usip_opcodes[i];
			if (f->nunits == 1 && !(f->flags & USIP_F_CTX) && tguard (f) && n_guarded16 < (int)R_ARRAY_SIZE (guarded16)) {
				guarded16[n_guarded16++] = i;
			}
		}
	}
	for (i = 0; i < n_guarded16 && guarded16[i] < lim; i++) {
		const UsipOpcode *f = &usip_opcodes[guarded16[i]];
		if (((f->flags & USIP_F_SLOT0) && !first) || ((f->flags & USIP_F_NOTSLOT0) && first) || (u & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, u, first, &ctxd, CM_FREE | CM_DEFER, false)) {
			continue;
		}
		bool has = false;
		const ut64 tg = target_value (f, u, pc, &has);
		const int st = has? eval_tguard (g, f, tguard (f), tg, 0): 0;
		if (st) {
			*guard = st;
			return f;
		}
	}
	return ip < 0? NULL: &usip_opcodes[ip];
}

/* ---------------------------------------------------------------------------------------------------- 32/48-bit matching */

/* the slot rules of a multi-unit form; the context forms of the H H T T group are admitted only inside that candidate,
 * the packet-prefix forms never (they are matched by match_prefix) */
static inline bool slot_ok(const UsipOpcode *f, bool first, bool hhtt) {
	if (f->flags & USIP_F_PREFIX) {
		return false;
	}
	if ((f->flags & USIP_F_CTX) && !(hhtt && (f->flags & USIP_F_HHTT))) {
		return false;
	}
	return !((f->flags & USIP_F_SLOT0) && !first) && !((f->flags & USIP_F_NOTSLOT0) && first);
}

/* first context-free match (the pairing predicate: "some form matches head + tail") */
static const UsipOpcode *match32(ut16 h, ut16 t, bool first) {
	const ut64 w = ((ut64)h << 16) | t;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 2 || !slot_ok (f, first, false) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE, false)) {
			continue;
		}
		return f;
	}
	return NULL;
}

/* status of a resolved multi-unit match */
enum { RS_NONE = 0, RS_OK, RS_WORD, RS_UNDO };

/* the first 32-bit form whose context-free constraints hold and whose deferred constraints hold too (a failing
 * position / packet-length / context constraint falls through to the next form of the cell); then the b.s guard
 * (RS_UNDO: the pair is undone into two 16-bit ops) and the target guard (RS_WORD: the pair is data) */
static const UsipOpcode *resolve32(const UsipGuardCtx *g, ut16 h, ut16 t, bool first, const CtxD *ctxd, bool force_hi, bool hhtt,
	ut64 pc, int dist, int *st, ut8 *guard) {
	const ut64 w = ((ut64)h << 16) | t;
	int i;
	*st = RS_NONE;
	*guard = USIP_G_NONE;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 2 || !slot_ok (f, first, hhtt) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE, force_hi)) {
			continue;
		}
		const ut8 fi = form_info (f);
		if ((fi & FI_DEFER) && !cons_ok (f, w, first, ctxd, CM_DEFER, force_hi)) {
			continue;
		}
		if ((fi & FI_BS) && first && bs_valid (g, pc, h)) {
			*st = RS_UNDO;
			return f;
		}
		const int tg = fi & FI_TG_MASK;
		if (tg) {
			bool has = false;
			const ut64 target = target_value (f, w, pc, &has);
			const int s = has? eval_tguard (g, f, tg, target, dist): 0;
			if (s) {
				*st = RS_OK;
				*guard = s;
			} else {
				*st = RS_WORD;
			}
			return f;
		}
		*st = RS_OK;
		return f;
	}
	return NULL;
}

/* round 0 of a two-tail head: does some 48-bit form match head + hi? */
static bool partial48(ut16 h, ut16 hi, bool first) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16);
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || !slot_ok (f, first, false)) {
			continue;
		}
		if ((w & (f->mask & 0xFFFFFFFF0000ULL)) == (f->value & 0xFFFFFFFF0000ULL)) {
			return true;
		}
	}
	return false;
}

/* first context-free 48-bit match (the pairing predicate of round 1) */
static const UsipOpcode *match48(ut16 h, ut16 hi, ut16 lo, bool first) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || !slot_ok (f, first, false) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE, false)) {
			continue;
		}
		return f;
	}
	return NULL;
}

static const UsipOpcode *resolve48(const UsipGuardCtx *g, ut16 h, ut16 hi, ut16 lo, bool first, const CtxD *ctxd, ut64 pc, int *st, ut8 *guard) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	int i;
	*st = RS_NONE;
	*guard = USIP_G_NONE;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || !slot_ok (f, first, false) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE, false)) {
			continue;
		}
		const ut8 fi = form_info (f);
		if ((fi & FI_DEFER) && !cons_ok (f, w, first, ctxd, CM_DEFER, false)) {
			continue;
		}
		const int tg = fi & FI_TG_MASK;
		if (tg) {
			bool has = false;
			const ut64 target = target_value (f, w, pc, &has);
			const int s = has? eval_tguard (g, f, tg, target, 0): 0;
			if (s) {
				*st = RS_OK;
				*guard = s;
			} else {
				*st = RS_WORD;
			}
			return f;
		}
		*st = RS_OK;
		return f;
	}
	return NULL;
}

static bool head_has_cands(ut16 h, int nunits, bool first) {
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != nunits || !slot_ok (f, first, false)) {
			continue;
		}
		const int sh = f->width - 16;
		if ((h & ((f->mask >> sh) & 0xFFFF)) == ((f->value >> sh) & 0xFFFF)) {
			return true;
		}
	}
	return false;
}

/* allowed tail counts of a head as a bitmask (bit n = n tails) */
static int ntails_allowed(ut16 h, bool first) {
	int s = 1;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (usip_must_pair); i++) {
		if ((h & usip_must_pair[i].mask) == usip_must_pair[i].value) {
			s = 0;
			break;
		}
	}
	if (!never_tail (h)) {
		if (head_has_cands (h, 2, first)) {
			s |= 2;
		}
		if (head_has_cands (h, 3, first)) {
			s |= 4;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (usip_must_pair); i++) {
		if ((h & usip_must_pair[i].mask) == usip_must_pair[i].value) {
			s &= usip_must_pair[i].tails;
		}
	}
	return s;
}

/* ---------------------------------------------------------------------------------------------------- assignments */

typedef struct {
	ut8 n;
	ut8 head[NU];
	ut8 nt[NU];
	ut8 t[NU][2];
} Asg;

typedef struct {
	Asg *a;
	int *aux;   /* parse_group: bad heads; group_parses: number of groups */
	int n, cap;
} AsgList;

static bool asglist_push(AsgList *l, const Asg *a, int aux) {
	if (l->n >= l->cap) {
		if (l->n >= ASG_HARD_CAP) {
			return false;
		}
		const int ncap = l->cap? l->cap * 2: 16;
		Asg *na = realloc (l->a, ncap * sizeof (Asg));
		int *naux = realloc (l->aux, ncap * sizeof (int));
		if (!na || !naux) {
			free (na? na: l->a);
			free (naux? naux: l->aux);
			l->a = NULL;
			l->aux = NULL;
			l->n = l->cap = 0;
			return false;
		}
		l->a = na;
		l->aux = naux;
		l->cap = ncap;
	}
	l->a[l->n] = *a;
	l->aux[l->n] = aux;
	l->n++;
	return true;
}

static void asglist_fini(AsgList *l) {
	free (l->a);
	free (l->aux);
	memset (l, 0, sizeof (*l));
}

/* the lexicographic key K of an assignment: the tuple of (head index, (tail indices...)) in head order */
static int asg_key_cmp(const Asg *a, const Asg *b) {
	const int n = R_MIN (a->n, b->n);
	int m, q;
	for (m = 0; m < n; m++) {
		if (a->head[m] != b->head[m]) {
			return a->head[m] < b->head[m]? -1: 1;
		}
		const int nt = R_MIN (a->nt[m], b->nt[m]);
		for (q = 0; q < nt; q++) {
			if (a->t[m][q] != b->t[m][q]) {
				return a->t[m][q] < b->t[m][q]? -1: 1;
			}
		}
		if (a->nt[m] != b->nt[m]) {
			return a->nt[m] < b->nt[m]? -1: 1;
		}
	}
	if (a->n != b->n) {
		return a->n < b->n? -1: 1;
	}
	return 0;
}

/* consistent readings of one group of n units (heads first, tails round-robin); only the ones with the fewest bare
 * heads without a named 16-bit reading are kept (parse_group); 5e0d is never a tail */
static void parse_group(const ut16 *units, int n, bool first_ok, AsgList *res) {
	AsgList tmp = { 0 };
	int k, i, j;
	if (n >= 3 && (units[n - 1] >> 15) && known16 (units[n - 1], true)) {
		/* last_unit_rule: <parse of the first n-1 units> + the closing named 16-bit op */
		AsgList sub = { 0 };
		parse_group (units, n - 1, first_ok, &sub);
		for (i = 0; i < sub.n; i++) {
			Asg a = sub.a[i];
			a.head[a.n] = n - 1;
			a.nt[a.n] = 0;
			a.n++;
			asglist_push (&tmp, &a, sub.aux[i]);
		}
		asglist_fini (&sub);
	}
	for (k = 1; k <= n; k++) {
		bool brk = false;
		for (i = 0; i < k - 1; i++) {
			if (units[i] >> 15) {
				brk = true;
			}
		}
		if (brk || ((units[k - 1] >> 15) && k != n)) {
			break;
		}
		int allowed[NU], vals[NU][3], nv[NU], idx[NU];
		int sum_max = 0, sum_min = 0;
		bool empty = false;
		for (i = 0; i < k; i++) {
			allowed[i] = (units[i] >> 15)? 1: ntails_allowed (units[i], i == 0 && first_ok);
			nv[i] = 0;
			for (j = 0; j < 3; j++) {
				if (allowed[i] & (1 << j)) {
					vals[i][nv[i]++] = j;
				}
			}
			if (!nv[i]) {
				empty = true;
			} else {
				sum_min += vals[i][0];
				sum_max += vals[i][nv[i] - 1];
			}
			idx[i] = 0;
		}
		const int need = n - k;
		if (empty || need > sum_max || need < sum_min) {
			continue;
		}
		/* itertools.product over the sorted allowed sets (the last head varies fastest) */
		for (;;) {
			int Ts[NU], sum = 0;
			for (i = 0; i < k; i++) {
				Ts[i] = vals[i][idx[i]];
				sum += Ts[i];
			}
			if (sum == need) {
				Asg a = { 0 };
				int ti = k, r;
				bool ok = true;
				for (i = 0; i < k; i++) {
					a.head[i] = i;
				}
				for (r = 0; r < 2 && ok; r++) {
					for (i = 0; i < k; i++) {
						if (Ts[i] <= r) {
							continue;
						}
						const ut16 h = units[i], t = units[ti];
						const bool first = i == 0 && first_ok;
						bool good;
						if (t == 0x5E0D) {
							/* 5e0d (.ctl15) is never a tail */
							good = false;
						} else if (Ts[i] == 1) {
							good = match32 (h, t, first) != NULL;
						} else if (r == 0) {
							good = partial48 (h, t, first);
						} else {
							good = match48 (h, units[a.t[i][0]], t, first) != NULL;
						}
						if (!good) {
							ok = false;
							break;
						}
						a.t[i][a.nt[i]++] = ti;
						ti++;
					}
				}
				if (ok) {
					int bad = 0;
					for (i = 0; i < k; i++) {
						if (Ts[i] == 0 && !known16 (units[i], i > 0)) {
							bad++;
						}
					}
					a.n = k;
					asglist_push (&tmp, &a, bad);
				}
			}
			/* odometer */
			for (i = k - 1; i >= 0; i--) {
				if (++idx[i] < nv[i]) {
					break;
				}
				idx[i] = 0;
			}
			if (i < 0) {
				break;
			}
		}
	}
	if (tmp.n) {
		int best = tmp.aux[0];
		for (i = 1; i < tmp.n; i++) {
			best = R_MIN (best, tmp.aux[i]);
		}
		for (i = 0; i < tmp.n; i++) {
			if (tmp.aux[i] == best) {
				asglist_push (res, &tmp.a[i], best);
			}
		}
	}
	asglist_fini (&tmp);
}

typedef struct {
	const ut16 *units;
	ut64 addrs[NU];
	int n;                          /* units of this parse (= the packet length for the packet_len constraints) */
	ut64 pk0;                       /* address of the packet start (the head index k of a unit = (addr - pk0) / 2) */
	const UsipGuardCtx *guard;
	AsgList memo[NU + 1];
	bool memo_done[NU + 1];
} Ctx;

static inline int kidx(const Ctx *c, ut64 pc) {
	return (int)((pc - c->pk0) / 2);
}

/* every reading of the packet suffix that starts at unit j0 as a sequence of groups (group_parses) */
static const AsgList *group_parses(Ctx *c, int j0, bool first_ok) {
	if (c->memo_done[j0]) {
		return &c->memo[j0];
	}
	AsgList *out = &c->memo[j0];
	const ut16 *units = c->units + j0;
	const int n = c->n - j0;
	int j, i, k;
	for (j = n; j >= 1; j--) {
		/* a group cannot start at a unit with bit 15 = 1, except the last one (rule R0: the final closer may be its
		 * own group even without a named reading) */
		if (j < n && (units[j] >> 15) && j != n - 1) {
			continue;
		}
		AsgList heads = { 0 };
		parse_group (units, j, first_ok, &heads);
		if (!heads.n) {
			continue;
		}
		if (j == n) {
			for (i = 0; i < heads.n; i++) {
				asglist_push (out, &heads.a[i], 1);
			}
		} else {
			const AsgList *rest = group_parses (c, j0 + j, false);
			for (i = 0; i < heads.n; i++) {
				for (k = 0; k < rest->n; k++) {
					Asg a = heads.a[i];
					const Asg *r = &rest->a[k];
					int m, q;
					for (m = 0; m < r->n; m++) {
						a.head[a.n] = r->head[m] + j;
						a.nt[a.n] = r->nt[m];
						for (q = 0; q < r->nt[m]; q++) {
							a.t[a.n][q] = r->t[m][q] + j;
						}
						a.n++;
					}
					asglist_push (out, &a, rest->aux[k] + 1);
				}
			}
		}
		asglist_fini (&heads);
		if (out->n > GROUP_PARSES_LIMIT) {
			break;
		}
	}
	c->memo_done[j0] = true;
	return out;
}

/* ---------------------------------------------------------------------------------------------------- decoding */

typedef struct {
	ut8 head, nt;
	ut8 t[USIP_MAX_TAILS];
	ut8 pseudo;
	ut8 guard;
	const UsipOpcode *op;
	ut8 kind;
	const char *mnem;
	ut64 w;
	bool has_target;
	ut64 target;
} Dec;

typedef struct {
	Dec d[NU];
	int n;
} DecList;

static ut64 target_value(const UsipOpcode *f, ut64 w, ut64 pc, bool *has) {
	int i;
	*has = false;
	for (i = 0; i < f->nfields; i++) {
		const int t = f->fields[i].type;
		if (t == USIP_A_DISP || t == USIP_A_UDISP) {
			*has = true;
			return (pc + (ut64)field_value (f, i, w)) & UT32_MAX;
		}
		if (t == USIP_A_ABSADDR && !strcmp (f->fields[i].name, "target")) {
			*has = true;
			return (ut64)field_value (f, i, w);
		}
	}
	return 0;
}

static void set_target(Dec *d, ut64 pc) {
	d->has_target = false;
	if (d->op) {
		d->target = target_value (d->op, d->w, pc, &d->has_target);
	}
}

static void set_form(Dec *d, const UsipOpcode *f, ut64 pc) {
	d->op = f;
	d->kind = f->kind;
	d->mnem = f->name;
	set_target (d, pc);
}

static Dec dec16(const UsipGuardCtx *g, ut64 pc, ut16 u, bool first, int pktlen, int k) {
	Dec d = { 0 };
	d.nt = 0;
	d.w = u;
	const UsipOpcode *f = match16 (g, u, first, pktlen, k, pc, &d.guard);
	if (!f) {
		d.pseudo = USIP_P_HWORD;
		d.kind = USIP_K_OTHER;
		d.mnem = ".hword";
		return d;
	}
	set_form (&d, f, pc);
	return d;
}

static void make_word(Dec *d) {
	d->pseudo = USIP_P_WORD_CTRL;
	d->op = NULL;
	d->kind = USIP_K_OTHER;
	d->mnem = ".word";
	d->has_target = false;
	d->guard = USIP_G_NONE;
}

/* decode head + tail; st = RS_* (RS_NONE: no form, .word; RS_WORD: a target guard failed, .word; RS_UNDO: the pair
 * must be undone) */
static Dec dec32(const UsipGuardCtx *g, ut64 pc, ut16 h, ut16 t, bool first, const CtxD *ctxd, bool force_hi, bool hhtt, int dist, int *st) {
	Dec d = { 0 };
	d.nt = 1;
	d.w = ((ut64)h << 16) | t;
	const UsipOpcode *f = resolve32 (g, h, t, first, ctxd, force_hi, hhtt, pc, dist, st, &d.guard);
	if (!f || *st == RS_WORD) {
		d.pseudo = *st == RS_WORD? USIP_P_WORD_CTRL: USIP_P_WORD;
		d.kind = USIP_K_OTHER;
		d.mnem = ".word";
		d.guard = USIP_G_NONE;
		return d;
	}
	if (*st == RS_UNDO) {
		return d;
	}
	set_form (&d, f, pc);
	return d;
}

static Dec dec48(const UsipGuardCtx *g, ut64 pc, ut16 h, ut16 hi, ut16 lo, bool first, const CtxD *ctxd) {
	Dec d = { 0 };
	int st;
	d.nt = 2;
	d.w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	const UsipOpcode *f = resolve48 (g, h, hi, lo, first, ctxd, pc, &st, &d.guard);
	if (!f || st == RS_WORD) {
		d.pseudo = USIP_P_W48;
		d.kind = USIP_K_OTHER;
		d.mnem = ".w48";
		d.guard = USIP_G_NONE;
		return d;
	}
	set_form (&d, f, pc);
	return d;
}

static inline bool is_named(const Dec *d) {
	return d->kind != USIP_K_OTHER && d->kind != USIP_K_FMT;
}

static inline bool is_ctrl_kind(int kind) {
	return kind == USIP_K_BR || kind == USIP_K_CALL || kind == USIP_K_LOOP;
}

/* kinds whose instructions carry a control-flow target  */
static inline bool is_ctrl_tgt(int kind) {
	switch (kind) {
	case USIP_K_BR: case USIP_K_BR16: case USIP_K_BR16D: case USIP_K_CALL: case USIP_K_CALL16:
	case USIP_K_CALLA: case USIP_K_JUMPA: case USIP_K_LOOP:
		return true;
	}
	return false;
}

/* slot-family unit [S][F][m][h][rrr][x][B][o3 o2 00]: low 12 bits != 0 (not nop/hi/lo), not addsp (F = 0, h = 1, rrr = 6) */
static bool is_slotfam(ut16 u) {
	if ((u & 3) != 0 || (u & 0x0FFF) == 0) {
		return false;
	}
	if (((u >> 14) & 1) == 0 && ((u >> 12) & 1) == 1 && ((u >> 9) & 7) == 6) {
		return false;
	}
	return true;
}

/* context rule op8_slot_split: two slot-family units form a pair of 16-bit ops unless the first is a ld/st head shape
 * (o3 = 0, bit 15 = 0) and the second a ld/st tail shape (F' = 1, tt != 11), or both are loads of the same register */
static bool slot_pair_ok(ut16 a, ut16 b) {
	if (!(is_slotfam (a | 0x8000) && is_slotfam (b | 0x8000))) {
		return false;
	}
	if ((a >> 15) == 0 && ((a >> 3) & 1) == 0 && ((b >> 14) & 1) == 1 && ((b >> 12) & 3) != 3) {
		return false;
	}
	if (((a >> 2) & 1) == 0 && ((b >> 2) & 1) == 0 && ((a >> 4) & 0x1F) == ((b >> 4) & 0x1F)) {
		return false;
	}
	return true;
}

static Dec slot_split(ut16 u, ut64 pc) {
	Dec d = { 0 };
	d.w = u;
	set_form (&d, &usip_opcodes[((u >> 2) & 1)? USIP_FORM_STSLOT_SPLIT: USIP_FORM_LDSLOT_SPLIT], pc);
	return d;
}

/* decode one assignment into instructions, applying the adjacency rules, the target guards, the b.s guard and the
 * context rules (decode_asg) */
static void decode_asg(const Ctx *c, const Asg *asg, bool first_ok, DecList *out) {
	const ut16 *units = c->units;
	int m;
	out->n = 0;
	for (m = 0; m < asg->n; m++) {
		const int i = asg->head[m];
		const ut16 h = units[i];
		const ut64 pc = c->addrs[i];
		const bool first = i == 0 && first_ok;
		const int k = kidx (c, pc);
		Dec d;
		Dec *prev = out->n? &out->d[out->n - 1]: NULL;
		if (asg->nt[m] == 0) {
			d = dec16 (c->guard, pc, h, first, c->n, k);
			/* ext_after_ldst: a final fX?7 (16-bit movi r8-15) two units after a ld/st whose single tail has S = 0 */
			if (d.op && !strcmp (d.mnem, "movi") && (h & 0xF10F) == 0xF007 && prev && (prev->kind == USIP_K_LD || prev->kind == USIP_K_ST)
				&& prev->nt == 1 && (units[prev->t[0]] >> 15) == 0 && prev->head == i - 2) {
				memset (&d, 0, sizeof (d));
				d.pseudo = USIP_P_EXT;
				d.kind = USIP_K_FMT;
				d.mnem = ".ext";
				d.w = h;
			}
			if (!strcmp (d.mnem, ".hword") && i > 0) {
				/* (the catch-all hword form matches every unit: these rules key on the mnemonic) */
				const ut16 prev_raw = units[i - 1];
				if (is_hi1010 (prev_raw) && !(prev && is_named (prev))) {
					/* lo_after_hi (not after a named instruction) */
					d.pseudo = USIP_P_LO;
					d.op = NULL;
					d.kind = USIP_K_FMT;
					d.mnem = ".lo";
				} else if ((prev_raw >> 15) == 0 && ((prev_raw >> 14) & 1) == 0 && ((prev_raw & 0xF) == 1 || (prev_raw & 0xF) == 4)
					&& (h >> 14) == 3 && (((h >> 12) & 3) == 1 || ((h >> 12) & 3) == 3) && prev && prev->head == i - 1 && prev->nt == 0) {
					/* set-on-compare split by the parser: re-merge */
					const UsipOpcode *f = match32 (prev_raw, h, false);
					if (f && !strncmp (f->form, "setcc_", 6)) {
						Dec nd = { 0 };
						nd.head = i - 1;
						nd.nt = 1;
						nd.t[0] = i;
						nd.w = ((ut64)prev_raw << 16) | h;
						set_form (&nd, f, c->addrs[i - 1]);
						nd.has_target = false;
						*prev = nd;
						continue;
					}
				}
			}
		} else if (asg->nt[m] == 1) {
			const int ti = asg->t[m][0];
			const ut16 t = units[ti];
			const int dist = ti - i;
			const int S = t >> 15;
			const CtxD ctxd = { c->n, k, units, i };
			/* H H T T: the two pairs of a 4-unit packet with the tails at +2 admit the hhtt context forms */
			const bool hh = c->n == 4 && dist == 2 && i <= 1;
			int st;
			d = dec32 (c->guard, pc, h, t, first, &ctxd, false, hh, dist, &st);
			if (hh && (st == RS_UNDO || !is_named (&d)) && is_hi1010 (h) && (h & 0xE) == 0 && (i == 0 || !fam_head (units[0]))) {
				/* decode_memFS(force): the hi(1010) shape of the head is ignored (never a hi syllable there) */
				int st2;
				Dec d2 = dec32 (c->guard, pc, h, t, first, &ctxd, true, true, dist, &st2);
				if (st2 == RS_OK && (d2.kind == USIP_K_LD || d2.kind == USIP_K_ST)) {
					d = d2;
					st = st2;
				}
			}
			bool undo = st == RS_UNDO;
			if (st == RS_OK && d.op) {
				if ((d.op->flags & USIP_F_ADJ1) && dist > 1) {
					/* immediate set-on-compare / add with rot12: tail adjacent only -> two 16-bit units instead */
					undo = true;
				} else if ((d.op->flags & USIP_F_ADJDEF) && dist < 2) {
					/* R-st1h: the F' = 0 st.h tail is deferred (+2 or farther); at +1 the pair is undone */
					undo = true;
				} else if ((d.op->flags & USIP_F_ADJ2) && dist != 2) {
					if (d.op->kind == USIP_K_LOOP && dist < 2) {
						/* loop #N with F = 1 and an ADJACENT S = 0 tail: two 16-bit ops */
						undo = true;
					} else {
						/* control tail with F' = 0: valid EXACTLY at +2 */
						make_word (&d);
					}
				} else if ((d.op->flags & USIP_F_ADJCTRL) && is_ctrl_kind (d.op->kind)
					&& (dist > 2 || (S == 1 && dist > 1 && strcmp (d.op->form, "loop_F0")))) {
					make_word (&d);
				} else if ((!strcmp (d.mnem, ".op8?") || !strcmp (d.mnem, ".op8.t?")) && dist == 1 && slot_pair_ok (h, t)) {
					/* context rule op8_slot_split: both units are slot-family units -> two 16-bit ops ldslot/stslot */
					Dec a = slot_split (h, pc), b = slot_split (t, c->addrs[ti]);
					a.head = i;
					b.head = ti;
					out->d[out->n++] = a;
					out->d[out->n++] = b;
					continue;
				}
			}
			if (undo) {
				Dec a = dec16 (c->guard, pc, h, first, c->n, k);
				Dec b = dec16 (c->guard, c->addrs[ti], t, false, c->n, kidx (c, c->addrs[ti]));
				a.head = i;
				b.head = ti;
				out->d[out->n++] = a;
				out->d[out->n++] = b;
				continue;
			}
			d.t[0] = ti;
		} else {
			const CtxD ctxd = { c->n, k, units, i };
			d = dec48 (c->guard, pc, h, units[asg->t[m][0]], units[asg->t[m][1]], first, &ctxd);
			d.t[0] = asg->t[m][0];
			d.t[1] = asg->t[m][1];
		}
		d.head = i;
		out->d[out->n++] = d;
	}
}

/* ---------------------------------------------------------------------------------------------------- scoring */

static bool mn_in_fam48(const char *mn) {
	static const char *const fam[] = { "lea", "lea?", "add", "ld.w", "ld.h", "ld.hu", "ld.b?", "ld.bu", "st.w", "st.h", "st.b", "mov32" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fam); i++) {
		if (!strcmp (mn, fam[i])) {
			return true;
		}
	}
	return false;
}

static bool ends_with(const char *s, const char *suffix) {
	const size_t ls = strlen (s), lx = strlen (suffix);
	return ls >= lx && !strcmp (s + ls - lx, suffix);
}

/* kinds of the 16-bit ops with a destination (the identical-units rule of 4-unit packets) */
static bool waw_kind(int kind) {
	switch (kind) {
	case USIP_K_ALU: case USIP_K_ALU32: case USIP_K_MOV: case USIP_K_MOVI: case USIP_K_MOVI21: case USIP_K_LD: case USIP_K_DSP:
	case USIP_K_MUL: case USIP_K_MOV32: case USIP_K_MOVI32: case USIP_K_MEM16: case USIP_K_BIT: case USIP_K_DSPACC: case USIP_K_CSR:
	case USIP_K_IO:
		return true;
	}
	return false;
}

/* rule R7: the context form of a bare first-slot unit (bit 15 = 0) read as .hword when the rest of the packet is
 * named: ldslot_S0 / stslot_S0 (slot family) or lea_sp_S0 (when no other instruction of the packet has a tail) */
static const UsipOpcode *r7_form(ut16 u, const DecList *dec) {
	static const int forms[3] = { USIP_FORM_LEA_SP_S0, USIP_FORM_LDSLOT_S0, USIP_FORM_STSLOT_S0 };
	int i, k;
	for (i = 0; i < 3; i++) {
		const UsipOpcode *f = &usip_opcodes[forms[i]];
		if ((u & f->mask) != f->value || (f->ncons && !cons_ok (f, u, true, NULL, CM_FREE | CM_DEFER, false))) {
			continue;
		}
		if (forms[i] == USIP_FORM_LEA_SP_S0) {
			bool tails = false;
			for (k = 1; k < dec->n; k++) {
				tails |= dec->d[k].nt > 0;
			}
			if (tails) {
				continue;
			}
		}
		return f;
	}
	return NULL;
}

/* the first instruction of the reading is a bare unit 0 without a name and every other instruction is named */
static bool r7_shape(const DecList *dec, bool first_ok) {
	int k;
	if (!first_ok || dec->n < 2 || dec->d[0].head != 0 || dec->d[0].nt || dec->d[0].kind != USIP_K_OTHER) {
		return false;
	}
	for (k = 1; k < dec->n; k++) {
		if (!is_named (&dec->d[k])) {
			return false;
		}
	}
	return true;
}

/* does the reading form the instruction (head, tails...) exactly? */
static bool formed(const DecList *dec, int head, int nt, int t0, int t1) {
	int i;
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		if (d->head == head && d->nt == nt && (nt < 1 || d->t[0] == t0) && (nt < 2 || d->t[1] == t1)) {
			return true;
		}
	}
	return false;
}

/* R-pen: do units[i..i+2] form a store-of-immediate triple?  head [0][F][00][000][x][B][0000] (not 0000/4000),
 * hi [0][1][L][imm13], lo with bit 15 = 1; with F = 0 only if imm13 = 0 */
static bool stimm_at(const ut16 *units, int n, int i) {
	if (i + 2 >= n) {
		return false;
	}
	const ut16 h = units[i], hi = units[i + 1], lo = units[i + 2];
	if ((h & 0xBE0F) != 0 || (h & 0x3FFF) == 0 || (hi >> 15) || !((hi >> 14) & 1) || !(lo >> 15)) {
		return false;
	}
	return ((h >> 14) & 1) == 1 || (hi & 0x1FFF) == 0;
}

typedef struct {
	int s0;      /* quarter units: unknown units + tie-break penalties */
	int ninsn;   /* I */
	int fv;      /* heads with a tail whose adjacency contradicts the F pattern */
	int adj;     /* adjacent tails (more is better) */
} Score;

static int score_cmp(const Score *a, const Score *b) {
	if (a->s0 != b->s0) {
		return a->s0 < b->s0? -1: 1;
	}
	if (a->ninsn != b->ninsn) {
		return a->ninsn < b->ninsn? -1: 1;
	}
	if (a->fv != b->fv) {
		return a->fv < b->fv? -1: 1;
	}
	if (a->adj != b->adj) {
		return a->adj > b->adj? -1: 1;
	}
	return 0;
}

/* score / fviol: unknown units, the documented tie-break penalties, I, Fv and A of the reading */
static Score score_reading(const Ctx *c, const Asg *asg, bool first_ok, DecList *dec) {
	const ut16 *units = c->units;
	const int n = c->n;
	Score s = { 0 };
	int unnamed = 0, pen = 0, i, j;
	ut8 tails_of7 = 0;
	decode_asg (c, asg, first_ok, dec);
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		const ut16 hu = units[d->head];
		if ((hu & 0xF) == 7 && d->nt) {
			tails_of7 |= 1 << d->t[0];
		}
		if (d->kind == USIP_K_OTHER || (d->op && (d->op->flags & USIP_F_RENAME))) {
			/* position renames (ld_w16_A_k0) are scored as their underlying reading (.sub? = unknown) */
			unnamed += 1 + d->nt;
		} else if (d->kind == USIP_K_FMT) {
			unnamed += 1;
			if (!strcmp (d->mnem, ".hi") || !strcmp (d->mnem, ".hilo")) {
				pen += Q (0.25);
			}
		} else if (d->nt == 2 && mn_in_fam48 (d->mnem) && is_hi1010 (units[d->t[0]]) && (((hu >> 4) & 0xF) == 14 || ((hu >> 4) & 0xF) == 15)) {
			pen += Q (0.5);
		} else if ((d->kind == USIP_K_LD || d->kind == USIP_K_ST) && d->nt == 1 && !((hu & 0xF) == 4 && ((units[d->t[0]] >> 12) & 3) == 2)) {
			/* alignment: ld.w/st.w(?) with f12 not a multiple of 4 (except the closed R-off.w band f12 = 3 mod 4 >= 0xf00),
			 * ld.h/st.h with an odd f12 */
			const int off = units[d->t[0]] & 0xFFF;
			const bool w = ends_with (d->mnem, ".w") || ends_with (d->mnem, ".w?");
			if ((w && (off & 3) && !((off & 3) == 3 && off >= 0xF00)) || (ends_with (d->mnem, ".h") && (off & 1))) {
				pen += Q (0.5);
			}
		}
		if (d->kind == USIP_K_ALU32 && !strcmp (d->mnem, "add") && d->nt == 1 && (hu & 0xC00F) == 0x4000 && (units[d->t[0]] & 0xF003) == 0xC001) {
			/* the f12 = 1 mod 4 pair relabelled add still pays the alignment penalty */
			pen += Q (0.5);
		}
		if (!d->nt && hu == 0x4000) {
			pen += Q (0.5);
		}
		if (d->op && d->has_target && is_ctrl_tgt (d->kind) && tguard (d->op)) {
			/* control reading whose target guard was accepted: breaks the exact ties against op16 || pair readings */
			pen -= Q (0.5);
		}
		if (d->nt == 1 && (hu & 0xFF0F) == 0x1D06 && known16 (units[d->t[0]], true)) {
			/* 1dX6 (16-bit st.w rB,[sp+4] shape) paired with a tail that is itself a named 16-bit op */
			pen += Q (0.5);
		}
		for (j = 0; j < d->nt; j++) {
			const ut16 u = units[d->t[j]];
			if ((u >> 14) == 0 && (u & 7) == 7 && ((u >> 8) & 1) == 0) {
				pen += Q (0.5);
			}
		}
	}
	for (j = 0; j < n; j++) {
		if (is_osyl (units[j]) && !(tails_of7 & (1 << j))) {
			pen += Q (0.75);
		}
	}
	if (n == 4) {
		/* two IDENTICAL units of a 4-unit packet with different roles (head with tail / 16-bit op without destination /
		 * 16-bit op with destination), or both 16-bit ops with a destination: +1.0 */
		ut16 ru[NU];
		int rr[NU], nr = 0;
		for (i = 0; i < dec->n; i++) {
			const Dec *d = &dec->d[i];
			const ut16 u = units[d->head];
			const int role = d->nt? 0: waw_kind (d->kind)? 2: 1;
			for (j = 0; j < nr && ru[j] != u; j++) {
				;
			}
			if (j < nr) {
				if (rr[j] != role || role == 2) {
					pen += Q (1.0);
				}
				rr[j] = role;
			} else {
				ru[nr] = u;
				rr[nr++] = role;
			}
		}
	}
	for (j = 0; j + 2 < n; j++) {
		const ut16 h3 = units[j], hi3 = units[j + 1], lo3 = units[j + 2];
		/* R-stimm (restricted): 4XX0 4000/6000 lo with lo S = 0 and imm14 < 0x100 not formed: +0.75 */
		if ((h3 & 0xFE0F) == 0x4000 && (h3 & 0x3FFF) != 0 && (hi3 == 0x4000 || hi3 == 0x6000) && (lo3 >> 15) == 0 && (lo3 & 0x3FFF) < 0x100
			&& !formed (dec, j, 2, j + 1, j + 2) && !stimm_at (units, n, j)) {
			pen += Q (0.75);
		}
		/* R-pen: a store-of-immediate triple (lo with bit 15 = 1) that the reading does not form: +0.75 */
		if (stimm_at (units, n, j) && !formed (dec, j, 2, j + 1, j + 2)) {
			pen += Q (0.75);
		}
	}
	if (r7_shape (dec, first_ok) && r7_form (units[0], dec)) {
		/* rule R7: the bare first-slot slot/lea? unit counts as named when the rest of the packet is named */
		unnamed--;
	}
	if (n >= 4) {
		/* the canonical mfcsr pair 4X37 e0nn (nn known) not paired in a packet of >= 4 units: +0.5 */
		for (j = 0; j + 1 < n; j++) {
			const ut16 a = units[j], b = units[j + 1];
			if ((a & 0xFE0F) == 0x4007 && (a & 0xF0) != 0 && (b & 0xFF00) == 0xE000 && ((mfcsr_known >> (b & 0xFF)) & 1) && (b & 0xFF) < 64
				&& !formed (dec, j, 1, j + 1, 0)) {
				pen += Q (0.5);
			}
		}
	}
	s.s0 = Q (unnamed) + pen;
	s.ninsn = dec->n;
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		if (!d->nt) {
			continue;
		}
		if (d->t[0] == d->head + 1) {
			s.adj++;
		}
		if (d->head + 1 < n) {
			/* Fv: head F = 0 and next unit bit 14 = 1 => the tail is adjacent, otherwise deferred */
			const bool pred_adj = ((units[d->head] >> 14) & 1) == 0 && ((units[d->head + 1] >> 14) & 1) == 1;
			if (pred_adj != (d->t[0] == d->head + 1)) {
				s.fv++;
			}
		}
	}
	return s;
}

/* when no group parse exists: pair adjacent units greedily (fallback) */
static void fallback(const Ctx *c, bool first_ok, DecList *out) {
	const ut16 *units = c->units;
	int i = 0;
	out->n = 0;
	while (i < c->n) {
		const ut16 h = units[i];
		const bool first = i == 0 && first_ok;
		if ((h >> 15) || i + 1 >= c->n) {
			Dec d = dec16 (c->guard, c->addrs[i], h, first, c->n, kidx (c, c->addrs[i]));
			d.head = i;
			out->d[out->n++] = d;
			i++;
			continue;
		}
		int st;
		Dec d = dec32 (c->guard, c->addrs[i], h, units[i + 1], first, NULL, false, false, 1, &st);
		if (st == RS_UNDO || !is_named (&d)) {
			Dec d16 = dec16 (c->guard, c->addrs[i], h, first, c->n, kidx (c, c->addrs[i]));
			if (is_named (&d16) || st == RS_UNDO) {
				d16.head = i;
				out->d[out->n++] = d16;
				i++;
				continue;
			}
		}
		d.head = i;
		d.t[0] = i + 1;
		out->d[out->n++] = d;
		i += 2;
	}
}

static int dec_cmp_head(const void *a, const void *b) {
	return (int)((const Dec *)a)->head - (int)((const Dec *)b)->head;
}

/* x008 in slot 0: positions of hi/lo by rule R; true when a call.abs/b.abs form matches */
static bool abs_prefix(const Ctx *c, int *hi, int *lo) {
	const ut16 *units = c->units;
	const int n = c->n;
	if (n < 3 || (units[0] & 0xB0FF) != 0x0008) {
		return false;
	}
	const int A = (units[0] >> 8) & 0xF;
	if (A != 0 && A != 6 && A != 7) {
		return false;
	}
	const int opF = (units[0] >> 14) & 1, XF = (units[1] >> 14) & 1;
	if (opF && XF) {
		*hi = 1; *lo = 2;
	} else if (!opF && !XF) {
		*hi = 2; *lo = 3;
	} else {
		*hi = 2; *lo = 4;
	}
	if (*lo >= n) {
		return false;
	}
	const UsipOpcode *f = match48 (units[0], units[*hi], units[*lo], true);
	return f && (f->kind == USIP_K_CALLA || f->kind == USIP_K_JUMPA);
}

/* the packet-prefix forms (bcc48 / bcc64): the first one whose mask, context-free constraints and target guard hold
 * over the first nunits units; a failing guard = the form is not taken */
static const UsipOpcode *match_prefix(const Ctx *c, ut64 *w_out, ut8 *guard) {
	int i, k;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (!(f->flags & USIP_F_PREFIX) || f->nunits > c->n) {
			continue;
		}
		ut64 w = 0;
		for (k = 0; k < f->nunits; k++) {
			w = (w << 16) | c->units[k];
		}
		if ((w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, true, NULL, CM_FREE, false)) {
			continue;
		}
		const int tg = tguard (f);
		if (tg) {
			bool has = false;
			const ut64 target = target_value (f, w, c->addrs[0], &has);
			const int st = has? eval_tguard (c->guard, f, tg, target, 0): 0;
			if (!st) {
				continue;
			}
			*guard = st;
		} else {
			*guard = USIP_G_NONE;
		}
		*w_out = w;
		return f;
	}
	return NULL;
}

static bool parse_packet(const UsipGuardCtx *g, const ut16 *units, const ut64 *addrs, int n, bool first_ok, ut64 pk0, DecList *best);

/* parse the units after a prefix instruction (indices rest[0..nr)) as an independent packet without control flow */
static bool rest_parse(const Ctx *c, const int *rest, int nr, DecList *best) {
	bool amb = false;
	int i, k;
	if (nr > 1) {
		ut16 ru[NU];
		ut64 ra[NU];
		DecList sub;
		for (k = 0; k < nr; k++) {
			ru[k] = c->units[rest[k]];
			ra[k] = c->addrs[rest[k]];
		}
		amb = parse_packet (c->guard, ru, ra, nr, false, c->pk0, &sub);
		for (i = 0; i < sub.n; i++) {
			Dec d = sub.d[i];
			d.head = rest[d.head];
			for (k = 0; k < d.nt; k++) {
				d.t[k] = rest[d.t[k]];
			}
			best->d[best->n++] = d;
		}
	} else if (nr == 1) {
		Dec d = dec16 (c->guard, c->addrs[rest[0]], c->units[rest[0]], false, 1, kidx (c, c->addrs[rest[0]]));
		d.head = rest[0];
		best->d[best->n++] = d;
	}
	return amb;
}

/* signature of a reading for the ambiguity test: (head, tails, mnemonic) of every instruction, by head */
static bool same_reading(const DecList *a, const DecList *b) {
	DecList sa = *a, sb = *b;
	int i, k;
	if (sa.n != sb.n) {
		return false;
	}
	qsort (sa.d, sa.n, sizeof (Dec), dec_cmp_head);
	qsort (sb.d, sb.n, sizeof (Dec), dec_cmp_head);
	for (i = 0; i < sa.n; i++) {
		const Dec *x = &sa.d[i], *y = &sb.d[i];
		if (x->head != y->head || x->nt != y->nt || strcmp (x->mnem, y->mnem)) {
			return false;
		}
		for (k = 0; k < x->nt; k++) {
			if (x->t[k] != y->t[k]) {
				return false;
			}
		}
	}
	return true;
}

/* the whole packet: the prefix forms, then every reading, scored with the layout order (s0, I, Fv, -A, K), then the
 * packet-level context rules (parse_packet).  Returns the ambiguity of the chosen reading. */
static bool parse_packet(const UsipGuardCtx *g, const ut16 *units, const ut64 *addrs, int n, bool first_ok, ut64 pk0, DecList *best) {
	int i, k;
	best->n = 0;
	Ctx c = { 0 };
	c.units = units;
	c.n = n;
	c.pk0 = pk0;
	c.guard = g;
	memcpy (c.addrs, addrs, n * sizeof (ut64));
	if (n == 1) {
		Dec d = dec16 (g, addrs[0], units[0], first_ok, 1, kidx (&c, addrs[0]));
		d.head = 0;
		best->d[best->n++] = d;
		return false;
	}
	if (first_ok && n >= 3) {
		ut64 w = 0;
		ut8 guard = USIP_G_NONE;
		int rest[NU], nr = 0, hi, lo;
		const UsipOpcode *pf = match_prefix (&c, &w, &guard);
		if (pf) {
			/* b<cond>.l prefix: one instruction, the rest of the packet is its delay slot */
			Dec d0 = { 0 };
			d0.head = 0;
			d0.nt = pf->nunits - 1;
			for (k = 0; k < d0.nt; k++) {
				d0.t[k] = k + 1;
			}
			d0.w = w;
			d0.guard = guard;
			set_form (&d0, pf, addrs[0]);
			best->d[best->n++] = d0;
			for (k = pf->nunits; k < n; k++) {
				rest[nr++] = k;
			}
			return rest_parse (&c, rest, nr, best);
		}
		if (abs_prefix (&c, &hi, &lo)) {
			const CtxD ctxd = { n, 0, units, 0 };
			Dec d0 = dec48 (g, addrs[0], units[0], units[hi], units[lo], true, &ctxd);
			d0.head = 0;
			d0.t[0] = hi;
			d0.t[1] = lo;
			best->d[best->n++] = d0;
			for (k = 1; k < n; k++) {
				if (k != hi && k != lo) {
					rest[nr++] = k;
				}
			}
			return rest_parse (&c, rest, nr, best);
		}
	}
	const AsgList *all = group_parses (&c, 0, first_ok);
	/* dedup by assignment */
	AsgList seen = { 0 };
	for (i = 0; i < all->n; i++) {
		const Asg *a = &all->a[i];
		for (k = 0; k < seen.n; k++) {
			if (!memcmp (&seen.a[k], a, sizeof (Asg))) {
				break;
			}
		}
		if (k == seen.n) {
			asglist_push (&seen, a, 0);
		}
	}
	if (n == 3 && first_ok && (units[0] >> 15) == 0 && (units[1] >> 15) == 0 && (units[2] >> 15) == 1 && ((units[2] >> 14) & 1) == 0) {
		/* the layout [head][16-bit op][control tail with F' = 0] is an explicit candidate (the group parser drops it when the
		 * middle unit has no named 16-bit reading); the same score decides (validated target or .word) */
		if (units[2] != 0x5E0D && match32 (units[0], units[2], true)) {
			Asg a = { 0 };
			a.n = 2;
			a.head[0] = 0;
			a.nt[0] = 1;
			a.t[0][0] = 2;
			a.head[1] = 1;
			for (k = 0; k < seen.n && memcmp (&seen.a[k], &a, sizeof (Asg)); k++) {
				;
			}
			if (k == seen.n) {
				asglist_push (&seen, &a, 0);
			}
		}
	}
	if (n == 4 && first_ok && (units[0] >> 15) == 0 && (units[1] >> 15) == 0 && (units[0] & 0xE) == 0 && (units[1] & 0xE) == 0
		&& (units[2] >> 15) == 0 && ((units[2] >> 14) & 1) == 1 && ((units[2] >> 12) & 3) != 3
		&& (units[3] >> 15) == 1 && ((units[3] >> 14) & 1) == 1 && ((units[3] >> 12) & 3) != 3 && units[2] != 0x5E0D && units[3] != 0x5E0D) {
		/* H H T T: the explicit candidate [h0][h1][t0 S=0][t1 S=1] with op 0/1 heads = two named ld/st in round-robin */
		Asg a = { 0 };
		DecList dd;
		a.n = 2;
		a.head[0] = 0;
		a.nt[0] = 1;
		a.t[0][0] = 2;
		a.head[1] = 1;
		a.nt[1] = 1;
		a.t[1][0] = 3;
		decode_asg (&c, &a, first_ok, &dd);
		if (dd.n == 2 && dd.d[0].nt && dd.d[1].nt && (dd.d[0].kind == USIP_K_LD || dd.d[0].kind == USIP_K_ST)
			&& (dd.d[1].kind == USIP_K_LD || dd.d[1].kind == USIP_K_ST)) {
			for (k = 0; k < seen.n && memcmp (&seen.a[k], &a, sizeof (Asg)); k++) {
				;
			}
			if (k == seen.n) {
				asglist_push (&seen, &a, 0);
			}
		}
	}
	bool amb;
	if (!seen.n) {
		fallback (&c, first_ok, best);
		amb = true;
	} else {
		/* the layout order (s0, I, Fv, -A, K): no prior, no group count */
		Score bs = { 0 };
		int nbest = -1;
		DecList cur;
		for (k = 0; k < seen.n; k++) {
			const Score s = score_reading (&c, &seen.a[k], first_ok, &cur);
			int cmp = nbest < 0? -1: score_cmp (&s, &bs);
			if (!cmp) {
				cmp = asg_key_cmp (&seen.a[k], &seen.a[nbest]);
			}
			if (cmp < 0) {
				bs = s;
				nbest = k;
				*best = cur;
			}
		}
		/* ambiguous: another reading ties on (s0, I, Fv, -A) and differs from the chosen one */
		amb = false;
		for (k = 0; k < seen.n && !amb; k++) {
			if (k == nbest) {
				continue;
			}
			const Score s = score_reading (&c, &seen.a[k], first_ok, &cur);
			amb = !score_cmp (&s, &bs) && !same_reading (best, &cur);
		}
		qsort (best->d, best->n, sizeof (Dec), dec_cmp_head);
	}
	asglist_fini (&seen);
	for (i = 0; i <= NU; i++) {
		asglist_fini (&c.memo[i]);
	}
	/* context rule bz_s_P4: a 2-unit packet opened by 4X?d/5X?d without a named reading */
	if (n == 2 && first_ok && (units[0] & 0xE00F) == 0x400D && units[0] != 0x5E0D && best->n && !is_named (&best->d[0])) {
		const UsipOpcode *f = &usip_opcodes[USIP_FORM_BZ_S_P4];
		const CtxD ctxd = { 2, 0, NULL, 0 };
		if ((units[0] & f->mask) == f->value && cons_ok (f, units[0], true, &ctxd, CM_FREE | CM_DEFER, false)) {
			Dec d0 = { 0 };
			d0.head = 0;
			d0.w = units[0];
			set_form (&d0, f, addrs[0]);
			Dec d1 = dec16 (g, addrs[1], units[1], false, 2, kidx (&c, addrs[1]));
			d1.head = 1;
			best->n = 0;
			best->d[best->n++] = d0;
			best->d[best->n++] = d1;
		}
	}
	/* context rules slot_S0_R7 / lea_sp_S0: bare first-slot .hword unit, every other instruction named */
	if (r7_shape (best, first_ok) && !strcmp (best->d[0].mnem, ".hword")) {
		const UsipOpcode *f = r7_form (units[0], best);
		if (f) {
			Dec *d0 = &best->d[0];
			memset (d0, 0, sizeof (*d0));
			d0->head = 0;
			d0->w = units[0];
			set_form (d0, f, addrs[0]);
			d0->has_target = false;
		}
	}
	/* context rule be79_prefix: bare [0][0][imm14] without a reading followed by be79 */
	for (k = 0; k + 1 < best->n; k++) {
		Dec *a = &best->d[k];
		const Dec *b = &best->d[k + 1];
		if (!a->nt && !b->nt && units[b->head] == 0xBE79 && (units[a->head] >> 14) == 0 && a->kind == USIP_K_OTHER) {
			a->pseudo = USIP_P_BE79;
			a->op = NULL;
			a->kind = USIP_K_OTHER;
			a->mnem = ".be79";
			a->nt = 1;
			a->t[0] = b->head;
			a->w = ((ut64)units[a->head] << 16) | units[b->head];
			a->has_target = false;
			a->guard = USIP_G_NONE;
			memmove (&best->d[k + 1], &best->d[k + 2], (best->n - k - 2) * sizeof (Dec));
			best->n--;
			break;
		}
	}
	return amb;
}

/* ---------------------------------------------------------------------------------------------------- API */

int usip_scan_units(const ut8 *buf, int len, ut16 *units, bool *truncated) {
	int n = 0;
	*truncated = false;
	while (n < NU && 2 * (n + 1) <= len) {
		units[n] = r_read_be16 (buf + 2 * n);
		n++;
		if (units[n - 1] & 0x8000) {
			return n;
		}
	}
	*truncated = n < NU;
	return n;
}

static inline bool kind_delays(int kind) {
	switch (kind) {
	case USIP_K_BR: case USIP_K_BR16: case USIP_K_BR16D: case USIP_K_CALL: case USIP_K_CALL16:
	case USIP_K_CALLA: case USIP_K_JUMPA: case USIP_K_RET: case USIP_K_CALLR: case USIP_K_JR:
		return true;
	}
	return false;
}

void usip_decode_packet(UsipPacket *pk, ut64 addr, const ut16 *units, int n, bool truncated, const UsipGuardCtx *g) {
	ut64 addrs[NU];
	DecList dec;
	int i, k;
	finfo_init ();
	memset (pk, 0, sizeof (*pk));
	n = R_MIN (R_MAX (n, 1), NU);
	pk->addr = addr;
	pk->nunits = n;
	pk->truncated = truncated;
	memcpy (pk->units, units, n * sizeof (ut16));
	for (i = 0; i < n; i++) {
		addrs[i] = addr + 2 * (ut64)i;
	}
	pk->ambiguous = parse_packet (g, units, addrs, n, true, addr, &dec);
	memset (pk->owner, 0xff, sizeof (pk->owner));
	for (i = 0; i < dec.n; i++) {
		const Dec *d = &dec.d[i];
		UsipInsn *in = &pk->insn[i];
		in->head = d->head;
		in->ntails = d->nt;
		for (k = 0; k < USIP_MAX_TAILS; k++) {
			in->tails[k] = d->t[k];
		}
		in->pseudo = d->pseudo;
		in->guard = d->guard;
		in->op = d->op;
		in->kind = d->kind;
		in->mnem = d->mnem;
		in->w = d->w;
		in->has_target = d->has_target;
		in->target = d->target;
		in->nvals = 0;
		if (d->op) {
			in->nvals = R_MIN (d->op->nfields, USIP_MAX_VALS);
			for (k = 0; k < in->nvals; k++) {
				in->vals[k] = field_value (d->op, k, d->w);
			}
		}
		pk->owner[d->head] = i;
		for (k = 0; k < d->nt; k++) {
			pk->owner[d->t[k]] = i;
		}
	}
	pk->ninsn = dec.n;
	/* every unit must have an owner (the readings cover the packet); be defensive anyway */
	for (i = 0; i < n; i++) {
		if (pk->owner[i] == 0xff && pk->ninsn < NU) {
			UsipInsn *in = &pk->insn[pk->ninsn];
			memset (in, 0, sizeof (*in));
			in->head = i;
			in->pseudo = USIP_P_HWORD;
			in->kind = USIP_K_OTHER;
			in->mnem = ".hword";
			in->w = units[i];
			pk->owner[i] = pk->ninsn++;
		}
	}
	pk->delay = pk->ninsn > 1 && pk->owner[0] != 0xff && kind_delays (pk->insn[pk->owner[0]].kind);
}

/* ---------------------------------------------------------------------------------------------------- text */

static void append_imm(RStrBuf *sb, st64 v) {
	if (v < 0) {
		r_strbuf_appendf (sb, "-0x%"PFMT64x, (ut64)(-v));
	} else {
		r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)v);
	}
}

static void format_operands(const UsipInsn *in, ut64 pc, RStrBuf *sb) {
	const UsipOpcode *op = in->op;
	const char *s = op->fmt;
	char tmp[256];
	size_t o = 0;
	RStrBuf ob;
	r_strbuf_init (&ob);
	while (*s) {
		if (*s != '{') {
			r_strbuf_append_n (&ob, s, 1);
			s++;
			continue;
		}
		const char *e = strchr (s, '}');
		if (!e) {
			r_strbuf_append (&ob, s);
			break;
		}
		const int idx = atoi (s + 1);
		const char *colon = memchr (s, ':', e - s);
		if (idx < 0 || idx >= in->nvals) {
			r_strbuf_append_n (&ob, s, e - s + 1);
			s = e + 1;
			continue;
		}
		const st64 v = in->vals[idx];
		if (colon) {
			if (v) {
				r_strbuf_append_n (&ob, colon + 1, e - colon - 1);
			}
			s = e + 1;
			continue;
		}
		switch (op->fields[idx].type) {
		case USIP_A_REG:
			r_strbuf_appendf (&ob, "r%d", (int)v);
			break;
		case USIP_A_ACC:
			r_strbuf_appendf (&ob, "A%d", (int)v);
			break;
		case USIP_A_ACCW: {
			static const char *const part[3] = { "lo", "hi", "ext" };
			r_strbuf_appendf (&ob, "A%d.%s", (int)(v / 3), part[v % 3]);
			break;
		}
		case USIP_A_CSR:
			r_strbuf_append (&ob, usip_csr_classic[v & 15]);
			break;
		case USIP_A_CSR_EXT:
			r_strbuf_appendf (&ob, "0x%02x", (unsigned)v);
			break;
		case USIP_A_DISP:
		case USIP_A_UDISP:
			r_strbuf_appendf (&ob, "0x%08"PFMT64x, (pc + (ut64)v) & UT32_MAX);
			break;
		case USIP_A_ABSADDR:
			r_strbuf_appendf (&ob, "0x%08"PFMT64x, (ut64)v);
			break;
		case USIP_A_MOVHI:
			r_strbuf_appendf (&ob, "0x%08"PFMT64x, (ut64)v & UT32_MAX);
			break;
		case USIP_A_OFFH:
		case USIP_A_OFFW:
			/* signed offset with an explicit sign: [rA+0x4], [rA-0x6] */
			r_strbuf_appendf (&ob, v < 0? "-0x%"PFMT64x: "+0x%"PFMT64x, (ut64)(v < 0? -v: v));
			break;
		case USIP_A_FLAG:
		case USIP_A_LOOPN:
			r_strbuf_appendf (&ob, "%d", (int)v);
			break;
		default:
			append_imm (&ob, v);
			break;
		}
		s = e + 1;
	}
	/* "[rA+-0x4]" -> "[rA-0x4]" */
	const char *t = r_strbuf_get (&ob);
	while (*t && o + 1 < sizeof (tmp)) {
		if (t[0] == '+' && t[1] == '-') {
			t++;
			continue;
		}
		tmp[o++] = *t++;
	}
	tmp[o] = 0;
	r_strbuf_fini (&ob);
	r_str_trim_tail (tmp);
	if (*tmp) {
		r_strbuf_append (sb, " ");
		r_strbuf_append (sb, tmp);
	}
}

void usip_insn_text(const UsipPacket *pk, int i, RStrBuf *sb) {
	const UsipInsn *in = &pk->insn[i];
	const ut64 pc = usip_unit_addr (pk, in->head);
	switch (in->pseudo) {
	case USIP_P_FORM:
		r_strbuf_append (sb, in->mnem);
		if (in->guard == USIP_G_UNVERIFIED) {
			/* target guard accepted without the function table */
			r_strbuf_append (sb, "?");
		}
		if (in->kind == USIP_K_OTHER && !usip_op_nargs (in->op)) {
			/* raw forms (.hword, .word, .alu16, .fill...): show the units */
			r_strbuf_appendf (sb, " 0x%0*"PFMT64x, 4 * (in->ntails + 1), in->w);
		} else {
			format_operands (in, pc, sb);
		}
		break;
	case USIP_P_HWORD:
		r_strbuf_appendf (sb, ".hword 0x%04x", (unsigned)(in->w & 0xFFFF));
		break;
	case USIP_P_WORD:
	case USIP_P_WORD_CTRL:
		r_strbuf_appendf (sb, ".word 0x%08x", (unsigned)(in->w & UT32_MAX));
		break;
	case USIP_P_W48:
		r_strbuf_appendf (sb, ".w48 0x%012"PFMT64x, (ut64)(in->w & 0xFFFFFFFFFFFFULL));
		break;
	case USIP_P_LO:
		r_strbuf_appendf (sb, ".lo 0x%04x", (unsigned)(in->w & 0xFFFF));
		break;
	case USIP_P_EXT:
		r_strbuf_appendf (sb, ".ext 0x%04x", (unsigned)(in->w & 0xFFFF));
		break;
	case USIP_P_BE79:
		r_strbuf_appendf (sb, ".be79 #0x%04x", (unsigned)((in->w >> 16) & 0x3FFF));
		break;
	default:
		r_strbuf_append (sb, in->mnem);
		break;
	}
}
