/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* uSIP packet decoder: a table-driven reading of VLIW packets (parse_group, group_parses, decode_asg, score, fviol,
 * parse_packet, apply_renames, decide_ties) over the generated form table usip_opcodes.h.  The reading chosen for a
 * packet is deterministic and prior-free: among the consistent readings
 * (every group split and head/tail assignment the table allows, plus the explicit candidates of the packet grammar)
 * the smallest (s0, I, Fv, -A, K) wins: s0 = unknown units + the documented tie-break penalties, I = number of
 * instructions, Fv = heads with a tail whose adjacency contradicts the F pattern, A = adjacent tails, K = the
 * lexicographic key of the assignment.  Readings tied on (s0, I, Fv, -A) go through the K-tie cascade before K
 * decides: dedup (identical instruction texts), nowaw (the only reading without a double register write) and du2 (a
 * differential use-definition score over the neighbouring packets the caller can supply).  The 48/64-bit b<cond>.l
 * prefix forms are matched on the first units of the packet before the layout; the post-layout rename entries of the
 * table relabel the decided instructions.  The only outside knowledge is what the caller passes in UsipGuardCtx
 * (packet starts of the function being decoded, function starts, the neighbouring packets). */

#include <r_util.h>
#include <math.h>
#include "usip_opcodes.h"
#include "usip_decode.h"

#define N_OPS ((int)(sizeof (usip_opcodes) / sizeof (usip_opcodes[0])))

/* the packet model of the table: the instructions of a packet execute in parallel and every read sees the state before the
 * packet; nothing below depends on an intra-packet order (the double-write rule R-waw and the K-tie cascade stay) */
#if !USIP_PACKET_EXEC_PARALLEL
#error "the uSIP decoder assumes the parallel packet execution model of the table"
#endif
#define NU USIP_MAX_UNITS
#define ASG_HARD_CAP 20000     /* generous bound; guards pathological input */
#define GROUP_PARSES_LIMIT 96  /* group_parses stops enumerating splits past this many readings */
#define DU2_W 8                /* window of the du2 scan, in packets */

/* scores are twentieths of a unit: 0.25 -> 5, 0.3 -> 6, 0.5 -> 10, 0.75 -> 15, 1.0 -> 20 */
#define Q(x) ((int)((x) * 20 + 0.5))

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
	case USIP_A_OFFB:
		/* byte displacement (R-offb): sext12(f[0] : f[10:1] : f[11]); bit 11 of the field is bit 0 of the displacement, bit 0 the sign */
		return sext (((raw & 1) << 11) | (raw & 0x7FE) | (raw >> 11), 12);
	case USIP_A_OFFW:
		/* 14-bit word displacement (W14): f12 = 2 mod 4 is +0x1000 + (f12 & ~3); f12 = 3 mod 4 >= 0x800 is a negative
		 * multiple of 4; the rest is f12 itself */
		if ((raw & 3) == 2) {
			return 0x1000 + (st64)(raw & 0xFFC);
		}
		return ((raw & 3) == 3 && raw >= 0x800)? 4 * sext (raw >> 2, 10): (st64)raw;
	case USIP_A_LOOPN:
		/* loop #N: the collected bits as is (head bits 13:5) */
		return (st64)raw;
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

/* index of the field called name, -1 when the form has none */
static int field_index(const UsipOpcode *op, const char *name) {
	int i;
	for (i = 0; i < op->nfields; i++) {
		if (!strcmp (op->fields[i].name, name)) {
			return i;
		}
	}
	return -1;
}

static inline bool is_hi1010(ut32 u) {
	return (u >> 15) == 0 && ((u >> 9) & 0xF) == 0xA;
}

static inline bool is_osyl(ut16 u) {
	return ((u >> 11) & 7) == 7;
}

/* ret / save / restore never take tails */
static inline bool never_tail_shape(ut16 h) {
	return (h & 0x3FFF) == 0x1EF9 || (h & 0x3F0F) == 0x1F05;
}

/* R-ctl15: units that are never a tail / heads that never take a tail (structure.packet.never_tail / never_head_with_tail) */
static bool unit_never_tail(ut16 u) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (usip_never_tail); i++) {
		if (usip_never_tail[i] == u) {
			return true;
		}
	}
	return false;
}

static bool head_never_with_tail(ut16 h) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (usip_never_head_with_tail); i++) {
		if (usip_never_head_with_tail[i] == h) {
			return true;
		}
	}
	return false;
}

/* the 48-bit value table (R-c48tab): exact values, and the upper 18 bits for the head:hi partial admission */
static bool c48_has(ut32 v) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (usip_c48_table); i++) {
		if (usip_c48_table[i] == v) {
			return true;
		}
	}
	return false;
}

static bool c48_hi18_has(ut32 hi18) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (usip_c48_table); i++) {
		if ((usip_c48_table[i] >> 14) == hi18) {
			return true;
		}
	}
	return false;
}

/* R-c48sym: the sorted table of data addresses already formed by the 48-bit family */
static bool c48sym_has(ut32 v) {
	int lo = 0, hi = (int)R_ARRAY_SIZE (usip_c48sym_table) - 1;
	while (lo <= hi) {
		const int mid = lo + (hi - lo) / 2;
		if (usip_c48sym_table[mid] == v) {
			return true;
		}
		if (usip_c48sym_table[mid] < v) {
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return false;
}

/* head of the 48-bit family [0][F][01][A][B][op in {0,4,5,6,7}]: never a hi(1010) nor ret/save/restore */
static bool fam_head(ut16 v) {
	const int op = v & 0xF;
	return (v >> 15) == 0 && ((v >> 12) & 3) == 1 && (op == 0 || (op >= 4 && op <= 7)) && !is_hi1010 (v) && !never_tail_shape (v);
}

/* R-movhi10: v is the high word of an IEEE-754 double with at most `digits` significant decimal digits (1e-9 <= |d| <= 1e12) */
static bool ieee_short(ut32 v, int digits) {
	const ut64 bits = (ut64)v << 32;
	double d;
	char buf[64];
	memcpy (&d, &bits, sizeof (d));
	if (d == 0 || !isfinite (d)) {
		return false;
	}
	const double a = fabs (d);
	if (a < 1e-9 || a > 1e12) {
		return false;
	}
	snprintf (buf, sizeof (buf), "%.*e", digits > 0? digits - 1: 0, a);
	return strtod (buf, NULL) == a;
}

/* ---------------------------------------------------------------------------------------------------- form info */

enum { TG_NONE = 0, TG_PK, TG_FN, TG_FN_OR_PK, TG_PK_ANY_OR_FN };
#define FI_TG_MASK 0x07   /* target-guard kind (TG_*) */
#define FI_BS      0x08   /* guard head_not_validated_bs */
#define FI_DEFER   0x10   /* has deferred (position / packet-length / context / tail-adjacency / R-br0) constraints */
#define FI_C48     0x20   /* 48-bit entry admitted by the value table (partial head:hi admission against the upper 18 bits) */
#define FI_STRADDLE 0x40  /* guard loop_b4_straddle16: bit 4 of the loop #N head must agree with "the packet at the end crosses a 16-byte line" */
#define FI_DONE    0x80
#define FI_XGUARD  0x100  /* guard not_over_validated_call32: the 64-bit b<cond>.l with a free extension unit yields to a validated 32-bit call / b of U0 + X */

static bool cons_deferred(const UsipCons *c) {
	int j;
	switch (c->op) {
	case USIP_C_PACKET_LEN: case USIP_C_PACKET_LEN_GE: case USIP_C_HEAD_INDEX: case USIP_C_HEAD_INDEX_GE: case USIP_C_CTX:
	case USIP_C_TAIL_ADJACENT: case USIP_C_BR0_CELLS: case USIP_C_BR0_CELLS_LIVE: case USIP_C_INSTR_INDEX:
		return true;
	case USIP_C_ANY:
		for (j = 0; j + 2 < c->nvals; j += 3) {
			switch (c->vals[j + 1]) {
			case USIP_ANY_TAIL_ADJACENT: case USIP_ANY_PACKET_LEN: case USIP_ANY_BR0_CELLS: case USIP_ANY_BR0_CELLS_LIVE:
			case USIP_ANY_INSTR_INDEX: case USIP_ANY_CTX:
				return true;
			case USIP_ANY_GUARD:
				if (c->vals[j + 2] == USIP_GD_TARGET_PACKET_START) {
					return true;
				}
				break;
			}
		}
		return false;
	}
	return false;
}

static bool cons_is_guard(int op) {
	switch (op) {
	case USIP_C_GUARD_TARGET_PACKET_START: case USIP_C_GUARD_TARGET_FUNCTION_START:
	case USIP_C_GUARD_TARGET_FN_OR_PACKET_START: case USIP_C_GUARD_HEAD_NOT_VALIDATED_BS:
	case USIP_C_GUARD_TARGET_PK_ANY_OR_FN: case USIP_C_GUARD_LOOP_B4_STRADDLE16: case USIP_C_GUARD_NOT_OVER_VALIDATED_CALL32:
		return true;
	}
	return false;
}

/* per-form summary of the constraint classes (computed once) */
static ut16 finfo[sizeof (usip_opcodes) / sizeof (usip_opcodes[0])];
static ut64 mfcsr_known;   /* CSR numbers of the canonical mfcsr pair (the `in` set of the mfcsr form) */

static void finfo_init(void) {
	int i, j;
	if (finfo[0] & FI_DONE) {
		return;
	}
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		ut16 v = 0;
		for (j = 0; j < f->ncons; j++) {
			switch (f->cons[j].op) {
			case USIP_C_GUARD_LOOP_B4_STRADDLE16: v |= FI_STRADDLE; break;
			case USIP_C_GUARD_NOT_OVER_VALIDATED_CALL32: v |= FI_XGUARD; break;
			case USIP_C_GUARD_TARGET_PACKET_START: v |= TG_PK; break;
			case USIP_C_GUARD_TARGET_FUNCTION_START: v |= TG_FN; break;
			case USIP_C_GUARD_TARGET_FN_OR_PACKET_START: v |= TG_FN_OR_PK; break;
			case USIP_C_GUARD_TARGET_PK_ANY_OR_FN: v |= TG_PK_ANY_OR_FN; break;
			case USIP_C_GUARD_HEAD_NOT_VALIDATED_BS: v |= FI_BS; break;
			case USIP_C_IN_C48TAB: v |= FI_C48; break;
			default:
				if (cons_deferred (&f->cons[j])) {
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

static inline ut16 form_info(const UsipOpcode *op) {
	return finfo[op - usip_opcodes];
}

/* the entries the packet parser matches: everything but the post-layout renames */
static inline bool parser_form(const UsipOpcode *f) {
	return !(f->flags & USIP_F_RENAME);
}

/* ---------------------------------------------------------------------------------------------------- target guards */

/* Guarded forms that may be read UNVERIFIED when the guard cannot be evaluated (the function table is absent, or the
 * forward target lies beyond the bytes the caller could see).  Measured on the sample the table was built from
 * (doc/usip.md): the unverified readings of these forms are right in nearly every case where they compete (call with
 * the F' = 0 tail at +2, b with the F' = 0 tail, compare-and-branch with immediate and the F' = 0 tail, beqz.d, the
 * b<cond>.l prefix forms with a forward target in their regular cell, loop #N with F = S = 1 and with F = 0 and the
 * tail adjacent, the op c F = 1 branches and the op 9 F = S = 0 cells with the F' = 0 tail at +2 (R-F0c / R-F0s0); the
 * S0F1 cells bne/blt/bgeu/bgtu/bge with immediate, beqz.d/bnez.d and the bleu register cell).  The other guarded
 * forms are NOT accepted unverified: bnez.d of the F = S = 0 cell (the cell is shared with the op C DSP pairs), the
 * register compare-and-branch with the F' = 0 tail (shared with .ctl15), loop rX with the F' = 0 tail (movi || mov
 * pairs; only the S = 1 tail at +2 after a head with F = 1 is accepted), loop #N with F = 0 and the tail at +2 and
 * with F = 1 and the S = 0 tail at +2, far b, the 16-bit call.s with bit 15 = 0 (only a small fraction of the shapes
 * are calls), the S0F1 cells beq/ble/bgt with immediate, the op 8 cells and the op d register cells.  w = the units
 * of the instruction. */
static bool unverified_ok(const UsipOpcode *op, int dist, ut64 w, ut64 pc, ut64 target) {
	static const char *const forms[] = {
		"call_F0", "b_F0", "beqz_d",
		"beq_imm8_F0", "bne_imm8_F0", "ble_imm8_F0", "blt_imm8_F0", "bgtu_imm8_F0", "bge_imm8_F0", "bgt_imm8_F0",
		/* (loop_imm_F1S0, the S = 0 tail at +2, is no longer accepted: its unverified readings are wrong too often) */
		"loop_imm_F1S1",
		/* the op c F = 1 S = 1 branches with the F' = 0 tail at +2 (R-F0c) and the op 9 F = S = 0 F' = 0 cells of >= 4 units (R-F0s0):
		 * right in nearly every unverified case (see doc/usip.md, "Target guards") */
		"beqz_F0c", "bnez_F0c", "bleu_rr_F0c", "bltu_rr_F0c", "bne_imm8_F0s0", "blt_imm8_F0s0",
		/* the loop #N entries with the F' = 0 tail at +2 and with h = 1 (N >= 128) and the S = 1 tail are accepted; the other
		 * h = 1 / m = 1 (N >= 256, loop #N?) entries are wrong too often when unverified and are not accepted */
		"loop_imm_F1_Fp0", "loop_imm_h1_F1S1",
		"bne_imm8_s0f1", "blt_imm8_s0f1", "bgeu_imm8_s0f1", "bgtu_imm8_s0f1", "bge_imm8_s0f1", "bleu_rr_s0f1", "bnez_s0f1", "beqz_s0f1",
		/* the entries whose target guard is a validation filter (R-tgt, R-br0): they were read without a guard before the
		 * filter existed, so without the function table the reading is kept and marked unverified; a known target that is
		 * not a packet start still rejects it (fall-through for the USIP_F_GUARDFT entries, .word for b, the next 16-bit
		 * entry for b.s) */
		"b_s_open", "b_near", "loop", "loop_ssq", "loop_b1", "loop_b1_ssq",
		"beq_imm8_d", "blt_imm8_d", "bltu_imm8_d", "bgtu_imm8_d", "bgt_imm8_d", "bne_rr_d", "beq_rr_d", "ble_rr_d", "blt_rr_d", "bltu_rr_d",
		"bne_d_m1", "bne_imm8_f0s0", "ble_imm8_f0s0", "bgeu_imm8_f0s0", "bge_imm8_f0s0", "bne.u8_imm8_f0s0", "beq.u8_imm8_f0s0", "bleu_rr_f0s0",
	};
	size_t i;
	if ((op->kind == USIP_K_BR || op->kind == USIP_K_BR16 || op->kind == USIP_K_BR16D) && strcmp (op->name, "b") && strcmp (op->name, "b.s")
		&& (st32)(ut32)(target - pc) < 0) {
		/* a conditional branch whose unknown target lies backward, before everything the caller has looked at, is never
		 * right (a conditional branch does not leave its function; a backward target inside the region decoded so far is
		 * known); calls and the unconditional b / b.s to an earlier function start are a different matter */
		return false;
	}
	if (op->flags & USIP_F_PREFIX) {
		/* the 48/64-bit b<cond>.l: unverified only in the regular cell (U1 low byte = 0 and tt = 00 on T: a forward displacement
		 * of less than 4096 units), where the unverified readings are right in nearly every case; the other cells of the 22-bit
		 * displacement (backward: above; +4096..+8191) and the 64-bit variant with a free extension unit (any 16-bit unit X) need
		 * the target validated */
		const ut16 u1 = (w >> 16) & 0xFFFF, t = w & 0xFFFF;
		return (u1 & 0xFF) == 0 && ((t >> 12) & 3) == 0 && !(op->nunits == 4 && ((op->mask >> 32) & 0xFFFF) == 0x8000);
	}
	if (!strcmp (op->form, "loop_imm_F0S0") || !strcmp (op->form, "loop_imm_h1_F0S0")) {
		return dist == 1;
	}
	if (!strcmp (op->form, "loop_F0") || !strcmp (op->form, "loop_F0_ssq")
		|| ((!strcmp (op->form, "loop_b1") || !strcmp (op->form, "loop_b1_ssq")) && !((w >> 14) & 1))) {
		/* loop rX with the F' = 0 tail (also loop rX, x16 when its tail has F' = 0): only the S = 1 tail at +2 after a head with F = 1 */
		return dist == 2 && ((w >> 30) & 1) && ((w >> 15) & 1);
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
static int eval_tguard(const UsipGuardCtx *g, const UsipOpcode *op, int tg, ut64 target, int dist, ut64 w, ut64 pc) {
	int pk = -1;
	if (tg == TG_PK || tg == TG_FN_OR_PK) {
		pk = (g && g->packet_start)? g->packet_start (g->user, target): -1;
	} else if (tg == TG_PK_ANY_OR_FN) {
		/* a packet start of any function of the image (the exception vectors), or a function start; without the
		 * packet_start_any callback the packet starts the caller knows (the same-function ones) stand in */
		pk = (g && g->packet_start_any)? g->packet_start_any (g->user, target):
			(g && g->packet_start)? g->packet_start (g->user, target): -1;
	}
	if (pk == 1) {
		return USIP_G_OK;
	}
	if (pk == 0) {
		/* a definite "not a packet start" rejects the reading even when the function starts are unknown: a target the
		 * caller could look at (inside the region it decoded, or within its lookahead) that is not a packet start cannot
		 * be a function start either */
		return 0;
	}
	if (tg == TG_FN || tg == TG_FN_OR_PK || tg == TG_PK_ANY_OR_FN) {
		const int fn = (g && g->function_start)? g->function_start (g->user, target): -1;
		if (fn == 1) {
			return USIP_G_OK;
		}
		if (fn == 0) {
			return 0;
		}
	}
	return unverified_ok (op, dist, w, pc, target)? USIP_G_UNVERIFIED: 0;
}

/* R-loopx16: does the packet that starts at `last` cross a 16-byte line?  1 / 0, or -1 when the caller cannot tell (the
 * packet at the loop end lies beyond the bytes at hand: the guard is then not evaluated, as for any decoder without that
 * packet in view).  The end of that packet is the next packet start after `last` (a whole-function scan uses the next packet
 * start inside the function, else the function end: the same address for a packet that closes). */
static int straddle16(const UsipGuardCtx *g, ut64 last) {
	const int n = (g && g->packet_units)? g->packet_units (g->user, last): -1;
	if (n < 1) {
		return -1;
	}
	return (last / 16) != ((last + 2 * (ut64)n - 2) / 16)? 1: 0;
}

/* the loop #N guard loop_b4_straddle16 of a resolved reading: bit 4 of the head (field b4) == straddle16(last); an unknown
 * packet at the end accepts */
static bool straddle_guard_ok(const UsipGuardCtx *g, const UsipOpcode *f, ut64 w, ut64 target) {
	const int fb = field_index (f, "b4");
	const int sv = straddle16 (g, target);
	if (fb < 0 || sv < 0) {
		return true;
	}
	return (field_value (f, fb, w) != 0) == (sv != 0);
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
	/* R-tgt: a function start (a tail call) validates the b.s too */
	return g && ((g->packet_start && g->packet_start (g->user, tg) == 1) || (g->function_start && g->function_start (g->user, tg) == 1));
}

/* ---------------------------------------------------------------------------------------------------- constraints */

/* context of the deferred constraints (position inside the packet, packet length, the other units, the tail of the
 * decided instruction, the cop registers of the packet) */
/* a decided instruction of a reading (head, tails, form or pseudo reading, target) */
typedef struct {
	ut8 head, nt;
	ut8 t[USIP_MAX_TAILS];
	ut8 pseudo;
	ut8 guard;
	ut8 loopq;          /* the loop #N? rule of the table (printed loop#? #N?, last=...) */
	const UsipOpcode *op;
	ut8 kind;
	const char *mnem;
	ut64 w;
	bool has_target;
	ut64 target;
} Dec;

typedef struct dec_list_t {
	Dec d[NU];
	int n;
} DecList;

typedef struct {
	int pktlen;          /* units of this parse (-1 = unknown) */
	int k;               /* unit index of the head inside the packet (-1 = unknown) */
	const ut16 *units;   /* units of this parse (NULL = unknown) */
	int i;               /* index of the head in units */
	int tail_dist;       /* distance of the single tail of the decided instruction (-1 = unknown / not applicable) */
	int tail_idx;        /* unit index of its first tail (-1 = none) */
	int cop_mask;        /* bit rA = some `cop rA` in the packet (-1 = unknown) */
	int hh_asg;          /* the assignment is the H H T T (C) layout (heads 0/1 with their tails at 2/3): 1 / 0 (-1 = unknown) */
	int bfpair_asg;      /* the assignment is the bit-field pair layout [op 7][op 7][tt = 01 S = 0][tt = 01 S = 1]: 1 / 0 (-1 = unknown) */
	const DecList *out;  /* the instructions decoded so far in this assignment (NULL = unknown) */
	const UsipPacket *pk;  /* the decided packet (the post-layout renames; NULL = unknown) */
	ut32 bf_dsts;        /* registers written by the WAW-kind instructions of the packet (bit r, bit 16 + r for rN!) */
	bool have_bf;        /* bf_dsts is known */
	int instr_index;     /* position of the instruction inside the decoded packet (-1 = unknown) */
	bool loop_guard;     /* R-w6h1: the first-slot unit is the head of a validated `loop rX` (ctx not_loop_reg_head fails) */
} CtxD;

#define CTXD_INIT(pl, kk, un, ii) { (pl), (kk), (un), (ii), -1, -1, -1, -1, -1, NULL, NULL, 0, false, -1, false }

#define CM_FREE  1   /* context-free constraints */
#define CM_DEFER 2   /* deferred constraints (packet_len, head_index, ctx, tail_adjacent) */

static int match16_plain_idx(ut16 u, bool first, int pktlen, int k);

/* is the unit a named 16-bit op (in tail position if tail)?  Format-only shapes count, loose syllables and the
 * stand-alone closer forms do not (the packet length is unknown here, so their packet_len constraint fails). */
static bool known16(ut16 u, bool tail) {
	const int i = match16_plain_idx (u | 0x8000, !tail, -1, -1);
	const UsipOpcode *f = i < 0? NULL: &usip_opcodes[i];
	return f && f->kind != USIP_K_OTHER && !(f->flags & USIP_F_UNKNOWN16);
}

static bool tail_adjacent_ok(const CtxD *ctxd, bool want) {
	/* unknown layout: accept */
	return !ctxd || ctxd->tail_dist < 0 || ((ctxd->tail_dist == 1) == want);
}

/* R-br0: the (B class, tail distance) cell of an F = 0 branch head is one of the entry's cells; the layout unknown = accepted */
static bool br0_ok(st64 B, ut32 mask, const CtxD *ctxd) {
	if (!ctxd || ctxd->tail_dist < 0) {
		return true;
	}
	const int cls = B == 0? 0: B == 15? 1: 2;
	return (ctxd->tail_dist == 1 || ctxd->tail_dist == 2) && ((mask >> (2 * cls + ctxd->tail_dist - 1)) & 1);
}

/* the weak cells hold only at the origins of a live trace, which the decoder does not have: never, once the layout is known */
static bool br0_live_ok(const CtxD *ctxd) {
	return !ctxd || ctxd->tail_dist < 0;
}

static bool ctx_cond_ok(const UsipOpcode *op, ut64 w, int cond, const CtxD *ctxd);
static bool rf0d_all_ok(const ut16 *units, int n, int i, int j);

static bool any_sub(const UsipOpcode *f, int op, st64 v, st64 val, ut64 w, const CtxD *ctxd) {
	switch (op) {
	case USIP_ANY_EQ: return v == val;
	case USIP_ANY_NE: return v != val;
	case USIP_ANY_LT: return v < val;
	case USIP_ANY_GE: return v >= val;
	case USIP_ANY_GT: return v > val;
	case USIP_ANY_INMASK: return v >= 0 && v < 31 && (((ut32)val >> v) & 1);
	case USIP_ANY_NOTINMASK: return !(v >= 0 && v < 31 && (((ut32)val >> v) & 1));
	case USIP_ANY_TAIL_ADJACENT: return tail_adjacent_ok (ctxd, val != 0);
	case USIP_ANY_PACKET_LEN: return ctxd && ctxd->pktlen == val;
	case USIP_ANY_GUARD:
		/* the tail is not a named 16-bit op; a target guard inside an any is evaluated by the context rule of the entry
		 * (bz_s_P5), never here */
		return val == USIP_GD_TAIL_NOT_NAMED16 && !known16 (w & 0xFFFF, true);
	case USIP_ANY_RANGE: return v >= (val & 0xFFFF) && v < (val >> 16);
	case USIP_ANY_BR0_CELLS: return br0_ok (v, (ut32)val, ctxd);
	case USIP_ANY_BR0_CELLS_LIVE: return br0_live_ok (ctxd);
	case USIP_ANY_INSTR_INDEX: return !ctxd || ctxd->instr_index < 0 || ctxd->instr_index == val;   /* unknown position: accept */
	case USIP_ANY_CTX: return ctx_cond_ok (f, w, (int)val, ctxd);
	}
	return false;
}

/* a named context condition (USIP_C_CTX, USIP_ANY_CTX) with the context at hand; an unknown context accepts */
static bool ctx_cond_ok(const UsipOpcode *op, ut64 w, int cond, const CtxD *ctxd) {
	int j;
	bool ok = true;
	if (cond == USIP_CTX_NOT_LOOP_REG_HEAD) {
		/* R-w6h1 loop guard: the first-slot unit is the head of a validated `loop rX` (match16 evaluates it with the packet) */
		return !(ctxd && ctxd->loop_guard);
	}
	if (cond == USIP_CTX_TARGET_BEYOND_PACKET || cond == USIP_CTX_DELAY_SLOT_NOT_WRITING_RA || cond == USIP_CTX_OP4IMM_HEAD_MULTIUNIT
		|| cond == USIP_CTX_SPLIT_UNIT || cond == USIP_CTX_DELAY_SLOT_OF_VALIDATED_BRANCH || cond == USIP_CTX_HEAD_UNNAMED_NOT_LSL0
		|| cond == USIP_CTX_SLOTC_PAIR || cond == USIP_CTX_CALL_WITHIN_2_PACKETS || cond == USIP_CTX_OP4IMM_HEAD || cond == USIP_CTX_ADD2_FREE_CLOSER) {
		/* evaluated by the explicit procedures (the bz.s context rules, the split pass, decode_asg, hw_rules, slotc_mark) */
		return true;
	}
	if (cond == USIP_CTX_TAIL_AT_PLUS2) {
		/* R-F0c / R-F0s0: the single tail EXACTLY at +2; at any other distance the entry falls through (unknown layout: accept) */
		return !ctxd || ctxd->tail_dist < 0 || ctxd->tail_dist == 2;
	}
	if (cond == USIP_CTX_RF0DALL_GUARDS) {
		/* rf0dall: the align guardians of the F' = 0 half-word load with any base (need the units of the packet) */
		return !ctxd || !ctxd->units || ctxd->tail_idx < 0 || rf0d_all_ok (ctxd->units, ctxd->pktlen, ctxd->i, ctxd->tail_idx);
	}
	if (!ctxd || !ctxd->units) {
		return true;
	}
	if (cond == USIP_CTX_NOT_EXT_OF_OP67) {
		/* a head at unit 1 with its low byte = 0 after a unit 0 with bit 15 = 0, F = 0 and op 6/7 is the extension
		 * word of that head */
		const ut16 h = (w >> (op->width - 16)) & 0xFFFF, u0 = ctxd->units[0];
		ok = !(ctxd->i == 1 && (h & 0xFF) == 0 && (u0 >> 15) == 0 && ((u0 & 0xF) == 6 || (u0 & 0xF) == 7) && ((u0 >> 14) & 1) == 0);
	} else if (cond == USIP_CTX_COP_RA_IN_PACKET) {
		/* some `cop rA` of the packet names the same register */
		const int fi = field_index (op, "rA");
		const st64 ra = fi >= 0? field_value (op, fi, w): -1;
		ok = ctxd->cop_mask >= 0 && ra >= 0 && ra < 16 && ((ctxd->cop_mask >> ra) & 1);
	} else if (cond == USIP_CTX_NOT_C48_LO_FOLLOWS) {
		/* the tail is not 5ffd followed by bfff / ffff (the 48-bit constant 0x7fff7fff) */
		const int ti = ctxd->tail_idx;
		ok = !(ti >= 0 && ctxd->units[ti] == 0x5FFD && ti + 1 < ctxd->pktlen
			&& (ctxd->units[ti + 1] == 0xBFFF || ctxd->units[ti + 1] == 0xFFFF));
	} else if (cond == USIP_CTX_B111_LAYOUT) {
		/* R-b111: the type-111 pair only in the 2-unit head + tail packet (head 0, adjacent closing tail), in the
		 * H H T T (C) layout or in the branch + ld/st, type-111 prefix and control + store layouts of >= 5 / 4 units
		 * (hh_asg); never an O syllable after an op 7 head */
		const int ti = ctxd->tail_idx, i0 = ctxd->i;
		if (ti >= 0) {
			const bool ht2 = ti == i0 + 1 && (ctxd->units[ti] >> 15) == 1 && i0 == 0;
			if (!(ht2 || ctxd->hh_asg > 0)) {
				ok = false;
			} else {
				bool op7 = false;
				for (j = 0; j < ti; j++) {
					op7 |= (ctxd->units[j] >> 15) == 0 && (ctxd->units[j] & 0xF) == 7;
				}
				ok = !(is_osyl (ctxd->units[ti]) && op7);
			}
		}
	} else if (cond == USIP_CTX_HHTT_SECOND_HEAD) {
		/* R-hhttF0: the instruction before is a named ld/st head (op 0/1) at i - 1 whose single tail is i + 1; this tail at i + 2 */
		const int ti = ctxd->tail_idx, i0 = ctxd->i;
		if (ti >= 0 && ctxd->out) {
			const Dec *p = ctxd->out->n? &ctxd->out->d[ctxd->out->n - 1]: NULL;
			ok = ti == i0 + 2 && i0 >= 1 && p && p->head == i0 - 1 && p->nt == 1 && p->t[0] == i0 + 1
				&& (p->kind == USIP_K_LD || p->kind == USIP_K_ST) && (ctxd->units[i0 - 1] & 0xE) == 0 && (ctxd->units[i0 - 1] >> 15) == 0;
		}
	} else if (cond == USIP_CTX_F0D_TRIPLE) {
		/* R-F0d: [head][adjacent unit with bits 15:14 = 01][F' = 0 tail at +2] */
		const int ti = ctxd->tail_idx, i0 = ctxd->i;
		if (ti >= 0) {
			ok = ti == i0 + 2 && i0 + 1 < ctxd->pktlen && (ctxd->units[i0 + 1] >> 14) == 1;
		}
	} else if (cond == USIP_CTX_BFPAIR) {
		/* R-bfpair: the bit-field pair layout with the pairs 0 -> 2 and 1 -> 3 */
		if (ctxd->tail_idx >= 0) {
			ok = ctxd->bfpair_asg > 0 && ctxd->tail_idx == ctxd->i + 2;
		}
	} else if (cond == USIP_CTX_BF_DST_NOT_WRITTEN) {
		/* the nowaw guardian of the bit-field renames: no WAW-kind instruction of the packet writes rB(!x) */
		if (ctxd->have_bf) {
			const int fb = field_index (op, "rB"), fx = field_index (op, "x");
			const st64 rb = fb >= 0? field_value (op, fb, w): -1, x = fx >= 0? field_value (op, fx, w): 0;
			ok = rb < 0 || !((ctxd->bf_dsts >> ((rb & 15) + (x? 16: 0))) & 1);
		}
	} else if (cond == USIP_CTX_BETWEEN_DSP_HEAD_AND_TAIL) {
		/* unit 1 between a DSP head (op 7 / op c, bit 15 = 0, with tails) and its tail */
		if (ctxd->pk) {
			const UsipPacket *pk = ctxd->pk;
			const UsipInsn *d0 = pk->owner[0] != 0xff? &pk->insn[pk->owner[0]]: NULL;
			int maxt = -1;
			if (d0) {
				for (j = 0; j < d0->ntails; j++) {
					maxt = R_MAX (maxt, (int)d0->tails[j]);
				}
			}
			ok = ctxd->i == 1 && d0 && d0->head == 0 && d0->ntails && (pk->units[0] >> 15) == 0
				&& ((pk->units[0] & 0xF) == 7 || (pk->units[0] & 0xF) == 0xC) && maxt > 1;
		}
	}
	/* USIP_CTX_REST_NAMED_NO_Q is evaluated by r7_form with the decoded packet */
	return ok;
}

/* the constraints of the classes in `which` hold for w; the target guards and the b.s guard are never evaluated here */
static bool cons_ok(const UsipOpcode *op, ut64 w, bool first, const CtxD *ctxd, int which) {
	int i, j;
	for (i = 0; i < op->ncons; i++) {
		const UsipCons *c = &op->cons[i];
		if (cons_is_guard (c->op) || !(which & (cons_deferred (c)? CM_DEFER: CM_FREE))) {
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
		case USIP_C_IN_C48TAB: ok = c48_has ((ut32)v); break;
		case USIP_C_IN_SET:
		case USIP_C_NOTIN_SET: {
			const UsipValueSet *vs = &usip_value_sets[c->vals[0]];
			bool in = false;
			for (j = 0; j < vs->n; j++) {
				in |= vs->v[j] == v;
			}
			ok = c->op == USIP_C_IN_SET? in: !in;
			break;
		}
		case USIP_C_BF_VALID: {
			/* R-bfpair: 1 <= w and w + pos <= 32 */
			const st64 pv = field_value (op, c->field2, w);
			ok = v >= 1 && v + pv <= 32;
			break;
		}
		case USIP_C_BR0_CELLS: ok = br0_ok (v, (ut32)c->vals[0], ctxd); break;
		case USIP_C_BR0_CELLS_LIVE: ok = br0_live_ok (ctxd); break;
		case USIP_C_GUARD_TAIL_NAMED16: ok = known16 (t, true); break;
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
		case USIP_C_IEEE_SHORT: ok = ieee_short ((ut32)v, (int)c->vals[0]); break;
		case USIP_C_TAIL_ADJACENT: ok = tail_adjacent_ok (ctxd, c->vals[0] != 0); break;
		case USIP_C_EQ_FIELDS: ok = v == field_value (op, c->field2, w); break;
		case USIP_C_NE_FIELDS: ok = v != field_value (op, c->field2, w); break;
		case USIP_C_PACKET_LEN: ok = ctxd && ctxd->pktlen == c->vals[0]; break;
		case USIP_C_PACKET_LEN_GE: ok = ctxd && ctxd->pktlen >= 0 && ctxd->pktlen >= c->vals[0]; break;
		case USIP_C_HEAD_INDEX: ok = ctxd && ctxd->k == c->vals[0]; break;
		case USIP_C_HEAD_INDEX_GE: ok = ctxd && ctxd->k >= 0 && ctxd->k >= c->vals[0]; break;
		case USIP_C_CTX: ok = ctx_cond_ok (op, w, (int)c->vals[0], ctxd); break;
		case USIP_C_INSTR_INDEX: ok = !ctxd || ctxd->instr_index < 0 || ctxd->instr_index == c->vals[0]; break;   /* unknown position: accept */
		case USIP_C_SLOT0_EXCLUDES_HEAD: {
			const ut16 h = (w >> (op->width - 16)) & 0xFFFF;
			ok = !(first && (h & (ut16)c->vals[0]) == (ut16)c->vals[1]);
			break;
		}
		case USIP_C_ANY:
			ok = false;
			for (j = 0; j + 2 < c->nvals; j += 3) {
				const int fld = c->vals[j];
				const st64 fv = fld != USIP_NOFIELD? field_value (op, fld, w): 0;
				ok |= any_sub (op, c->vals[j + 1], fv, c->vals[j + 2], w, ctxd);
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

/* first matching 16-bit form WITHOUT a target guard (context-only and rename forms excluded); cached per (packet
 * length class, head index class, slot, unit).  The 16-bit packet_len constraints only test 1, 2 and >= 2, the
 * head_index ones 0 and >= 2 (checked by the generator), hence the classes. */
static ut16 k16cache[4][3][2][0x10000];   /* 0 = unknown, 0xffff = none, else index + 1 */

static inline int pl_class(int pktlen) {
	return pktlen < 0? 0: pktlen == 1? 1: pktlen == 2? 2: 3;
}

static inline int k_class(int k) {
	return k == 0? 0: k >= 2? 2: 1;
}

/* the table scan behind the cache; lg = the unit is the head of a validated `loop rX` (R-w6h1 loop guard: the entries with
 * ctx not_loop_reg_head do not match) */
static int match16_scan(ut16 u, bool first, int pktlen, int k, bool lg) {
	CtxD ctxd = CTXD_INIT (pktlen, k, NULL, 0);
	int i;
	ctxd.loop_guard = lg;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 1 || !parser_form (f) || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)
			|| ((f->flags & USIP_F_NOTSLOT0) && first) || (u & f->mask) != f->value || tguard (f)) {
			continue;
		}
		if (f->ncons && !cons_ok (f, u, first, &ctxd, CM_FREE | CM_DEFER)) {
			continue;
		}
		return i;
	}
	return -1;
}

static int match16_plain_idx(ut16 u, bool first, int pktlen, int k) {
	ut16 *slot = &k16cache[pl_class (pktlen)][k_class (k)][first? 1: 0][u];
	if (*slot) {
		return *slot == 0xffff? -1: *slot - 1;
	}
	const int i = match16_scan (u, first, pktlen, k, false);
	*slot = i < 0? 0xffff: i + 1;
	return i;
}

/* the packet being parsed (parse_packet sets it): the R-w6h1 loop guard reads the units after the head */
typedef struct usip_parse_ctx_t Ctx;
static const Ctx *g_cur = NULL;
static bool loop_reg_head(const Ctx *c, ut64 pc);

/* 16-bit forms with a target guard (call.s with bit 15 = 0), in table order */
static int guarded16[8];
static int n_guarded16 = -1;

static ut64 target_value(const UsipOpcode *f, ut64 w, ut64 pc, bool *has);

/* first matching 16-bit form: a guarded form that precedes the plain match is taken when its guard validates */
static const UsipOpcode *match16(const UsipGuardCtx *g, ut16 u, bool first, int pktlen, int k, ut64 pc, ut8 *guard) {
	/* R-w6h1 loop guard: a first-slot op f unit with F = 1, m = 0, h = 1, x = 0 and B in {0, 1} that is the head of a validated
	 * `loop r{8+rrr}` is matched outside the cache, with ctx not_loop_reg_head failing */
	const bool lg = first && (u & 0x71EF) == 0x500F && g_cur && loop_reg_head (g_cur, pc);
	const int ip = lg? match16_scan (u, first, pktlen, k, true): match16_plain_idx (u, first, pktlen, k);
	const int lim = ip < 0? N_OPS: ip;
	const CtxD ctxd = CTXD_INIT (pktlen, k, NULL, 0);
	int i;
	*guard = USIP_G_NONE;
	if (n_guarded16 < 0) {
		n_guarded16 = 0;
		for (i = 0; i < N_OPS; i++) {
			const UsipOpcode *f = &usip_opcodes[i];
			if (f->nunits == 1 && parser_form (f) && !(f->flags & USIP_F_CTX) && tguard (f) && n_guarded16 < (int)R_ARRAY_SIZE (guarded16)) {
				guarded16[n_guarded16++] = i;
			}
		}
	}
	for (i = 0; i < n_guarded16 && guarded16[i] < lim; i++) {
		const UsipOpcode *f = &usip_opcodes[guarded16[i]];
		if (((f->flags & USIP_F_SLOT0) && !first) || ((f->flags & USIP_F_NOTSLOT0) && first) || (u & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, u, first, &ctxd, CM_FREE | CM_DEFER)) {
			continue;
		}
		bool has = false;
		const ut64 tg = target_value (f, u, pc, &has);
		const int st = has? eval_tguard (g, f, tguard (f), tg, 0, u, pc): 0;
		if (st) {
			*guard = st;
			return f;
		}
	}
	return ip < 0? NULL: &usip_opcodes[ip];
}

/* ---------------------------------------------------------------------------------------------------- 32/48-bit matching */

/* R-b111: the packet (or delay-slot sub-packet) being parsed has exactly two units: the b111 context forms (ld.bu / st.b
 * with a named 16-bit tail) are admitted by the grammar (set by parse_packet) */
static bool g_ht2 = false;

/* the slot rules of a multi-unit form; the context forms of the H H T T group (and of the b111 group) are admitted only
 * inside that candidate, the b111 group also in the 2-unit head + tail packet (ht2), the f0ctx group never here (decode_asg
 * tries it on the .word pairs), the packet-prefix forms never (they are matched by match_prefix), the rename forms never
 * (apply_renames) */
static inline bool slot_ok(const UsipOpcode *f, bool first, bool hhtt, bool ht2) {
	if ((f->flags & USIP_F_PREFIX) || !parser_form (f)) {
		return false;
	}
	if ((f->flags & USIP_F_CTX) && !((hhtt && (f->flags & (USIP_F_HHTT | USIP_F_B111))) || (ht2 && (f->flags & USIP_F_B111)))) {
		return false;
	}
	return !((f->flags & USIP_F_SLOT0) && !first) && !((f->flags & USIP_F_NOTSLOT0) && first);
}

/* first context-free match (the pairing predicate: "some form matches head + tail"; in a 2-unit packet the b111 context
 * forms count) */
static const UsipOpcode *match32(ut16 h, ut16 t, bool first, bool ht2) {
	const ut64 w = ((ut64)h << 16) | t;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 2 || !slot_ok (f, first, false, ht2) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE)) {
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
 * (RS_UNDO: the pair is undone into two 16-bit ops) and the target guard (RS_WORD: the pair is data; on an
 * USIP_F_GUARDFT entry a failing guard falls through, and when no entry is left the pair is undone: RS_UNDO) */
static const UsipOpcode *resolve32(const UsipGuardCtx *g, ut16 h, ut16 t, bool first, const CtxD *ctxd, bool hhtt, bool ht2,
	ut64 pc, int dist, int *st, ut8 *guard) {
	const ut64 w = ((ut64)h << 16) | t;
	bool fell = false;
	int i;
	*st = RS_NONE;
	*guard = USIP_G_NONE;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 2 || !slot_ok (f, first, hhtt, ht2) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE)) {
			continue;
		}
		const ut8 fi = form_info (f);
		if ((fi & FI_DEFER) && !cons_ok (f, w, first, ctxd, CM_DEFER)) {
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
			int s = has? eval_tguard (g, f, tg, target, dist, w, pc): 0;
			if (s && (fi & FI_STRADDLE) && !straddle_guard_ok (g, f, w, target)) {
				/* R-loopx16: bit 4 of the loop #N head contradicts the 16-byte line of its end: the pair is data, like a failing
				 * target guard (the false loops are the forward 64-bit b<cond>.l with an extension unit) */
				s = 0;
			}
			if (s) {
				*st = RS_OK;
				*guard = s;
			} else if (f->flags & USIP_F_GUARDFT) {
				/* R-tgt / R-br0: the known target is a filter, the next reading of the cell is tried */
				fell = true;
				continue;
			} else {
				*st = RS_WORD;
			}
			return f;
		}
		*st = RS_OK;
		return f;
	}
	*st = fell? RS_UNDO: RS_NONE;
	return NULL;
}

/* round 0 of a two-tail head: does some 48-bit form match head + hi?  The entries admitted by the value table need
 * head[13:9]:hi[12:0] to be the upper 18 bits of some table value. */
static bool partial48(ut16 h, ut16 hi, bool first) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16);
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || !slot_ok (f, first, false, false)) {
			continue;
		}
		if ((w & (f->mask & 0xFFFFFFFF0000ULL)) != (f->value & 0xFFFFFFFF0000ULL)) {
			continue;
		}
		if ((form_info (f) & FI_C48) && !c48_hi18_has ((((ut32)h >> 9) & 0x1F) << 13 | (hi & 0x1FFF))) {
			continue;
		}
		return true;
	}
	return false;
}

/* first context-free 48-bit match (the pairing predicate of round 1) */
static const UsipOpcode *match48(ut16 h, ut16 hi, ut16 lo, bool first) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || !slot_ok (f, first, false, false) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE)) {
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
		if (f->nunits != 3 || !slot_ok (f, first, false, false) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, NULL, CM_FREE)) {
			continue;
		}
		const ut8 fi = form_info (f);
		if ((fi & FI_DEFER) && !cons_ok (f, w, first, ctxd, CM_DEFER)) {
			continue;
		}
		const int tg = fi & FI_TG_MASK;
		if (tg) {
			bool has = false;
			const ut64 target = target_value (f, w, pc, &has);
			const int s = has? eval_tguard (g, f, tg, target, 0, w, pc): 0;
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

static bool head_has_cands(ut16 h, int nunits, bool first, bool ht2) {
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != nunits || !slot_ok (f, first, false, ht2)) {
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
	if (head_never_with_tail (h)) {
		/* R-ctl15: 5e0d / 1e0d never take a tail */
		return 1;
	}
	if (!never_tail_shape (h)) {
		/* R-b111: in a 2-unit packet the ld.bu / st.b context forms (named 16-bit tail) admit the tail */
		if (head_has_cands (h, 2, first, g_ht2)) {
			s |= 2;
		}
		if (head_has_cands (h, 3, first, false)) {
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
 * heads without a named 16-bit reading are kept (parse_group); the units of usip_never_tail are
 * never a tail */
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
						if (unit_never_tail (t)) {
							good = false;
						} else if (Ts[i] == 1) {
							good = match32 (h, t, first, g_ht2) != NULL;
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

struct usip_parse_ctx_t {
	const ut16 *units;
	ut64 addrs[NU];
	int n;                          /* units of this parse (= the packet length for the packet_len constraints) */
	ut64 pk0;                       /* address of the packet start (the head index k of a unit = (addr - pk0) / 2) */
	const UsipGuardCtx *guard;
	AsgList memo[NU + 1];
	bool memo_done[NU + 1];
};

static inline int kidx(const Ctx *c, ut64 pc) {
	return (int)((pc - c->pk0) / 2);
}

/* R-w6h1 loop guard: is the unit at pc followed, at +1 or +2 of the packet being parsed, by a [S][0][11][d12] tail whose
 * end pc + d12 is a packet start of the function after pc?  Then it is the head of `loop r{8+rrr}` and the W6 h = 1 cell
 * st.h rB, [r{8+rrr}] does not apply to it. */
static bool loop_reg_head(const Ctx *c, ut64 pc) {
	const UsipGuardCtx *g = c->guard;
	int i, j;
	if (!g || !g->packet_start) {
		return false;
	}
	for (i = 0; i < c->n && c->addrs[i] != pc; i++) {
		;
	}
	if (i == c->n) {
		return false;
	}
	for (j = i + 1; j <= i + 2 && j < c->n; j++) {
		const ut16 t = c->units[j];
		if (((t >> 12) & 3) == 3 && ((t >> 14) & 1) == 0) {
			const ut64 tg = (pc + (t & 0xFFF)) & UT32_MAX;
			if (tg > pc && g->packet_start (g->user, tg) == 1) {
				return true;
			}
		}
	}
	return false;
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


static void dec_text(const Dec *d, ut64 pc, RStrBuf *sb);
static int reg_token(const char *s, bool prev_word, int *len);

/* the register token at s (rN, rN!, sp, LR): its bit, -1 when s does not start with one */
static inline int reg_token_at(const char *s, int *len) {
	return reg_token (s, false, len);
}

/* the first operand of the instruction's text is the register `reg` followed by one of the characters of `follow` */
static bool first_operand_is(const Dec *d, ut64 pc, const char *reg, const char *follow) {
	RStrBuf sb;
	bool r = false;
	r_strbuf_init (&sb);
	dec_text (d, pc, &sb);
	const char *sp = strchr (r_strbuf_get (&sb), ' ');
	if (sp) {
		while (*sp == ' ') {
			sp++;
		}
		const size_t n = strlen (reg);
		r = !strncmp (sp, reg, n) && sp[n] && strchr (follow, sp[n]);
	}
	r_strbuf_fini (&sb);
	return r;
}

static bool waw_kind(int kind);

/* the register destination of a decided instruction by the WAW oracle: the first operand of a WAW-kind instruction when it
 * is a register followed by a comma, stores excluded by mnemonic (every st* and, with skip_io, iow); the bit of the register
 * (16 + r for rN!), -1 when it writes no GPR */
static int dec_dst(const Dec *d, ut64 pc, bool skip_io) {
	RStrBuf sb;
	int r = -1;
	if (!waw_kind (d->kind) || !d->mnem || !(isalpha ((unsigned char)d->mnem[0]) || d->mnem[0] == '_') || !strncmp (d->mnem, "st", 2)
		|| (skip_io && !strcmp (d->mnem, "iow"))) {
		return -1;
	}
	r_strbuf_init (&sb);
	dec_text (d, pc, &sb);
	const char *sp = strchr (r_strbuf_get (&sb), ' ');
	if (sp) {
		int len = 0;
		while (*sp == ' ') {
			sp++;
		}
		const int t = reg_token_at (sp, &len);
		if (t >= 0) {
			const char *q = sp + len;
			while (*q == ' ') {
				q++;
			}
			if (*q == ',') {
				r = t;
			}
		}
	}
	r_strbuf_fini (&sb);
	return r;
}

/* the readings tied on (s0, I, Fv, -A) of a packet (sorted by head, in K order, distinct signatures) */
typedef struct {
	DecList *d;
	int n, cap;
	bool first_ok;   /* the ties come from the top-level parse (false: from the rest of a prefix packet) */
} TieList;

static bool tielist_push(TieList *l, const DecList *d) {
	if (l->n >= l->cap) {
		const int ncap = l->cap? l->cap * 2: 8;
		DecList *nd = realloc (l->d, ncap * sizeof (DecList));
		if (!nd) {
			return false;
		}
		l->d = nd;
		l->cap = ncap;
	}
	l->d[l->n++] = *d;
	return true;
}

static void tielist_fini(TieList *l) {
	free (l->d);
	l->d = NULL;
	l->n = l->cap = 0;
}

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
static Dec dec32(const UsipGuardCtx *g, ut64 pc, ut16 h, ut16 t, bool first, const CtxD *ctxd, bool hhtt, bool ht2, int dist, int *st) {
	Dec d = { 0 };
	d.nt = 1;
	d.w = ((ut64)h << 16) | t;
	const UsipOpcode *f = resolve32 (g, h, t, first, ctxd, hhtt, ht2, pc, dist, st, &d.guard);
	if (*st == RS_UNDO) {
		/* the b.s guard, or a fall-through guard with no form left: the pair is undone into two 16-bit ops */
		return d;
	}
	if (!f || *st == RS_WORD) {
		d.pseudo = *st == RS_WORD? USIP_P_WORD_CTRL: USIP_P_WORD;
		d.kind = USIP_K_OTHER;
		/* a failed guard of the op C compare-and-branch cell leaves the DSP-shaped pair, printed .dsp (the pair
		 * stays unnamed data: the name is the only difference) */
		d.mnem = (*st == RS_WORD && (h & 0xF) == 0xC && ((t >> 12) & 3) == 0)? ".dsp": ".word";
		d.guard = USIP_G_NONE;
		return d;
	}
	set_form (&d, f, pc);
	if (USIP_LOOPQ_ENABLED && f->kind == USIP_K_LOOP && !strcmp (f->name, "loop#")) {
		/* R-loopx16 (the loop #N? rule of the table): a loop #N reading with N = 0 or whose end lies at pc + 2^k prints loop #N?
		 * (the ? after the count); the layout candidate loopcand does not admit it */
		const int fn = field_index (f, "N");
		bool q = fn >= 0 && field_value (f, fn, d.w) == USIP_LOOPQ_N_EQ;
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (usip_loopq_d12); i++) {
			q |= (t & 0xFFF) == usip_loopq_d12[i];
		}
		if (q) {
			d.mnem = "loop#?";
			d.loopq = 1;
		}
	}
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

/* every control kind (CTRL_KINDS: the re-read middle unit of R-F0d is never one) */
static inline bool is_ctrl_any(int kind) {
	switch (kind) {
	case USIP_K_BR: case USIP_K_BR16: case USIP_K_BR16D: case USIP_K_CALL: case USIP_K_CALL16: case USIP_K_CALLA:
	case USIP_K_JUMPA: case USIP_K_RET: case USIP_K_CALLR: case USIP_K_JR: case USIP_K_LOOP:
		return true;
	}
	return false;
}

/* kinds whose instructions carry a control-flow target (CTRL_TGT) */
static inline bool is_ctrl_tgt(int kind) {
	switch (kind) {
	case USIP_K_BR: case USIP_K_BR16: case USIP_K_BR16D: case USIP_K_CALL: case USIP_K_CALL16:
	case USIP_K_CALLA: case USIP_K_JUMPA: case USIP_K_LOOP:
		return true;
	}
	return false;
}

static bool in_list(const char *s, const char *const *list, size_t n);

/* rf0dall (ctx rf0dall_guards): (1) the unit at +2 (the tail j) does not decode in tail position as a trusted 16-bit op nor as a
 * control kind, (2) the head is not the unit 4400 right after an op f head with x = 1 (call r8 || mov || mov), (3) the middle
 * unit read as a 16-bit op does not write r14 / sp (the parity of f12 is in the pattern of the rf0dall_* entries) */
static bool rf0d_all_ok(const ut16 *units, int n, int i, int j) {
	static const char *const conf16[] = { "mov", "inc", "dec", "rsub", "add", "addi", "mul", "st.w", "ld.w", "mfacc", "lsl", "lsr", "asr", "sub",
		"and", "or", "xor", "sext16", "zext16", "movi", "st.h", "ld.h", "ld.hu", "st.b", "ld.bu" };
	const Dec dj = dec16 (NULL, 0, units[j], false, -1, -1);
	if (in_list (dj.mnem, conf16, R_ARRAY_SIZE (conf16)) || is_ctrl_any (dj.kind)) {
		return false;
	}
	if (i >= 1 && (units[i - 1] & 0x810F) == 0x010F && (units[i] & 0xFFF0) == 0x4400) {
		return false;
	}
	if (n >= 0 && i + 1 < n) {
		const Dec d1 = dec16 (NULL, 0, units[i + 1], false, -1, -1);
		if (is_named (&d1) && first_operand_is (&d1, 0, "r14", ", \t")) {
			return false;
		}
	}
	return true;
}

/* R-slotc (ctx slotc_pair): the tail [S][F'][00][a][X][rd] with rd in {4, c} and a != 8, not the (0, 0) cell with head B = 0
 * (saturate), low 12 bits > 1 when F' = 1, and a pair reading without a firm name (.dsp / .word, the ? DSP cells, or mac /
 * mul.a / mul3216.a / L_mac.a with the accumulator nibble rd > 3) */
static bool slotc_ok(ut16 h, ut16 t, const Dec *d) {
	static const char *const qdsp[] = { "msu?", "shr.a?", "mac.9a?", "mac.92?" };
	static const char *const acc[] = { "mac", "mul.a", "mul3216.a", "L_mac.a" };
	if (((t >> 12) & 3) != 0 || ((t & 0xF) != 4 && (t & 0xF) != 0xC) || ((t >> 8) & 0xF) == 8) {
		return false;
	}
	if ((t & 0x0FF0) == 0 && (h & 0x00F0) == 0) {
		return false;
	}
	if (((t >> 14) & 1) == 1 && (t & 0x0FFF) <= 1) {
		return false;
	}
	if (!is_named (d) && (!strcmp (d->mnem, ".dsp") || !strcmp (d->mnem, ".word"))) {
		return true;
	}
	if (in_list (d->mnem, qdsp, R_ARRAY_SIZE (qdsp))) {
		return true;
	}
	return (t & 0xF) > 3 && in_list (d->mnem, acc, R_ARRAY_SIZE (acc));
}

/* the immediate after the first '#' of the instruction's text (the value of mov32 r15, #X / addi r14, #imm); *ok = found */
static st64 text_imm(const Dec *d, ut64 pc, bool *ok) {
	RStrBuf sb;
	st64 v = 0;
	r_strbuf_init (&sb);
	dec_text (d, pc, &sb);
	const char *hs = strchr (r_strbuf_get (&sb), '#');
	*ok = hs != NULL;
	if (hs) {
		v = (st64)strtoll (hs + 1, NULL, 0);
	}
	r_strbuf_fini (&sb);
	return v;
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

/* the pairs 0 -> 2 and 1 -> 3 of an assignment */
static bool pairs_0213(const Asg *asg, bool *rest_from4) {
	bool t0 = false, t1 = false, r4 = true;
	int m, q;
	for (m = 0; m < asg->n; m++) {
		if (asg->head[m] == 0) {
			t0 = asg->nt[m] == 1 && asg->t[m][0] == 2;
		} else if (asg->head[m] == 1) {
			t1 = asg->nt[m] == 1 && asg->t[m][0] == 3;
		} else {
			r4 &= asg->head[m] >= 4;
			for (q = 0; q < asg->nt[m]; q++) {
				r4 &= asg->t[m][q] >= 4;
			}
		}
	}
	if (rest_from4) {
		*rest_from4 = r4;
	}
	return t0 && t1;
}

/* a branch head with F = 0 (op 8/9/a/c/d, bit 15 = 0) */
static inline bool br_f0_head(ut16 u) {
	const int op = u & 0xF;
	return (u >> 15) == 0 && ((u >> 14) & 1) == 0 && (op == 8 || op == 9 || op == 0xA || op == 0xC || op == 0xD);
}

/* the assignment is the H H T T (C) layout: op 0/1 heads at units 0 and 1 (bit 15 = 0) with their tails at 2 and 3;
 * 4 units, or 5 with a 16-bit closer.  R-brHHTT: also [branch head F = 0 at 0 -> 2][op 0/1 head at 1 -> 3] + the rest
 * in packets of >= 5 units whose units 2 and 3 have S = 0 and F' = 1. */
static bool hhtt_asg(const Ctx *c, const Asg *asg) {
	const ut16 *u = c->units;
	if (c->n >= 5 && br_f0_head (u[0]) && !(u[1] & 0xE) && !(u[1] >> 15) && !(u[2] >> 15) && ((u[2] >> 14) & 1) && !(u[3] >> 15) && ((u[3] >> 14) & 1)
		&& pairs_0213 (asg, NULL)) {
		return true;
	}
	if ((c->n != 4 && c->n != 5) || (u[0] & 0xE) || (u[1] & 0xE) || (u[0] >> 15) || (u[1] >> 15)) {
		return false;
	}
	return pairs_0213 (asg, NULL);
}

/* R-b111pre: H H T T (op 0/1 heads at 0 and 1, tails at 2 and 3) as the PREFIX of a packet of >= 5 units, every other
 * instruction in units >= 4 */
static bool hhtt_asg_prefix(const Ctx *c, const Asg *asg) {
	const ut16 *u = c->units;
	bool r4 = false;
	if (c->n < 5 || (u[0] & 0xE) || (u[1] & 0xE) || (u[0] >> 15) || (u[1] >> 15)) {
		return false;
	}
	return pairs_0213 (asg, &r4) && r4;
}

/* R-b111ctl: [op e head at 0 -> tail 2][op 1 head at 1 -> tail 3] in exactly 4 units with unit 2 S = 0 and unit 3 S = 1
 * (the round-robin of the type-111 store after a control head) */
static bool ctl_hhtt_asg(const Ctx *c, const Asg *asg) {
	const ut16 *u = c->units;
	if (c->n != 4 || (u[0] >> 15) || (u[0] & 0xF) != 0xE || (u[1] >> 15) || (u[1] & 0xF) != 1 || (u[2] >> 15) != 0 || (u[3] >> 15) != 1) {
		return false;
	}
	return pairs_0213 (asg, NULL);
}

/* the layouts in which the b111 context forms hold (ctx b111_layout): H H T T (C), R-brHHTT, R-b111pre, R-b111ctl */
static inline bool b111_asg(const Ctx *c, const Asg *asg) {
	return hhtt_asg (c, asg) || hhtt_asg_prefix (c, asg) || ctl_hhtt_asg (c, asg);
}

/* the grammar's rejections for an explicit candidate: a tail on ret / save / restore or on a head that never takes one,
 * a unit that is never a tail */
static bool bad_assignment(const Ctx *c, const Asg *asg) {
	int m, q;
	for (m = 0; m < asg->n; m++) {
		const ut16 u = c->units[asg->head[m]];
		if (asg->nt[m] && (never_tail_shape (u) || head_never_with_tail (u))) {
			return true;
		}
		for (q = 0; q < asg->nt[m]; q++) {
			if (unit_never_tail (c->units[asg->t[m][q]])) {
				return true;
			}
		}
	}
	return false;
}

/* P2W / P2H prefix: the DECODED reading starts with H H T T (op 0/1 heads at 0 and 1 with their tails at 2 and 3) and every
 * other instruction lies in units >= 4 */
static bool hhtt_prefix_dec(const Ctx *c, const DecList *dec) {
	const ut16 *u = c->units;
	bool t0 = false, t1 = false;
	int i, q;
	if (c->n < 5 || (u[0] & 0xE) || (u[1] & 0xE) || (u[0] >> 15) || (u[1] >> 15)) {
		return false;
	}
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		if (d->head == 0) {
			t0 = d->nt == 1 && d->t[0] == 2;
		} else if (d->head == 1) {
			t1 = d->nt == 1 && d->t[0] == 3;
		} else {
			if (d->head < 4) {
				return false;
			}
			for (q = 0; q < d->nt; q++) {
				if (d->t[q] < 4) {
					return false;
				}
			}
		}
	}
	return t0 && t1;
}

/* R-bfpair: a valid bit-field cell: tt = 01, c != 3, 1 <= w and w + rotr5(p) <= 32 */
static bool bf_cell_valid(ut16 t) {
	if (((t >> 12) & 3) != 1) {
		return false;
	}
	const int cc = (t >> 10) & 3, a = (t >> 5) & 0x1F, b = t & 0x1F;
	return cc != 3 && a >= 1 && a + ((b >> 1) | ((b & 1) << 4)) <= 32;
}

/* the assignment is [op 7][op 7][tail tt = 01 S = 0][tail tt = 01 S = 1] with both cells valid and the pairs 0 -> 2, 1 -> 3 */
static bool bfpair_asg(const Ctx *c, const Asg *asg) {
	const ut16 *u = c->units;
	bool t0 = false, t1 = false;
	int m;
	if (c->n != 4 || asg->n != 2) {
		return false;
	}
	for (m = 0; m < asg->n; m++) {
		t0 |= asg->head[m] == 0 && asg->nt[m] == 1 && asg->t[m][0] == 2;
		t1 |= asg->head[m] == 1 && asg->nt[m] == 1 && asg->t[m][0] == 3;
	}
	if (!t0 || !t1 || (u[0] >> 15) || (u[0] & 0xF) != 7 || (u[1] >> 15) || (u[1] & 0xF) != 7) {
		return false;
	}
	return (u[2] >> 15) == 0 && (u[3] >> 15) == 1 && bf_cell_valid (u[2]) && bf_cell_valid (u[3]);
}

/* the instruction is one of the f0ctx entries of R-F0d (rf0d_*: the deferred tail of a head with base sp) */
static inline bool is_rf0d(const Dec *d) {
	return d->nt == 1 && d->op && (d->op->flags & USIP_F_F0CTX) && !strncmp (d->op->form, "rf0d", 4);
}

/* decode one assignment into instructions, applying the adjacency rules, the target guards, the b.s guard and the
 * context rules (decode_asg) */
static void decode_asg(const Ctx *c, const Asg *asg, bool first_ok, DecList *out) {
	const ut16 *units = c->units;
	int m, j;
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
			if (!strcmp (d.mnem, ".movi6?") && first_ok && i > 0 && out->n && out->d[0].head == 0
				&& (out->d[0].kind == USIP_K_BR || out->d[0].kind == USIP_K_BR16D) && out->d[0].has_target
				&& c->guard && c->guard->packet_start && c->guard->packet_start (c->guard->user, out->d[0].target) == 1) {
				/* R-movi6d: the .movi6? closer in the delay slot of a validated branch at unit 0 is movi rA, #simm6 (form
				 * movi6_dsbr, ctx delay_slot_of_validated_branch): named in the score */
				memset (&d, 0, sizeof (d));
				d.w = h;
				set_form (&d, &usip_opcodes[USIP_FORM_MOVI6_DSBR], pc);
			}
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
				bool fam_before = false;
				for (j = 0; j < i && !fam_before; j++) {
					fam_before = fam_head (units[j]);
				}
				if (fam_before && is_hi1010 (h)) {
					/* hi_lo_fam_before: a loose hi syllable of the 48-bit family after a head of that family */
					d.pseudo = USIP_P_HI;
					d.op = &usip_opcodes[USIP_FORM_HI1010_LOOSE];
					d.kind = USIP_K_FMT;
					d.mnem = ".hi";
				} else if (fam_before && is_hi1010 (prev_raw) && !(prev && is_named (prev))) {
					/* hi_lo_fam_before: the unit after an unclaimed hi (not after a named instruction) */
					d.pseudo = USIP_P_LO;
					d.op = NULL;
					d.kind = USIP_K_FMT;
					d.mnem = ".lo";
				} else if ((prev_raw >> 15) == 0 && ((prev_raw >> 14) & 1) == 0 && ((prev_raw & 0xF) == 1 || (prev_raw & 0xF) == 4)
					&& (h >> 14) == 3 && (((h >> 12) & 3) == 1 || ((h >> 12) & 3) == 3) && prev && prev->head == i - 1 && prev->nt == 0) {
					/* set-on-compare split by the parser: re-merge */
					const UsipOpcode *f = match32 (prev_raw, h, false, false);
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
			const int S = t >> 15, Fp = (t >> 14) & 1;
			CtxD ctxd = CTXD_INIT (c->n, k, units, i);
			ctxd.tail_dist = dist;
			ctxd.tail_idx = ti;
			ctxd.hh_asg = b111_asg (c, asg)? 1: 0;
			ctxd.bfpair_asg = bfpair_asg (c, asg)? 1: 0;
			ctxd.out = out;
			/* H H T T: the two pairs of a 4-unit packet with the tails at +2 admit the hhtt context forms (and the b111 ones); also
			 * the H H T T prefix of a >= 5-unit packet (R-b111pre) and the branch + ld/st prefix (R-brHHTT): the context forms are
			 * admitted and ctx b111_layout decides */
			const bool hh = dist == 2 && i <= 1 && (c->n == 4 || (c->n >= 5 && ((units[2] >> 14) & 1) == 1 && ((units[3] >> 14) & 1) == 1
				&& (units[1] & 0xE) == 0 && ((units[0] & 0xE) == 0 || br_f0_head (units[0]))));
			/* R-b111: the 2-unit head + tail packet admits the b111 context forms */
			const bool ht2 = c->n == 2 && i == 0 && dist == 1;
			int st;
			d = dec32 (c->guard, pc, h, t, first, &ctxd, hh, ht2, dist, &st);
			bool undo = st == RS_UNDO;
			if (st == RS_OK && d.op) {
				if ((d.op->flags & USIP_F_ADJ1) && dist > 1) {
					/* immediate set-on-compare / add with rot12: tail adjacent only -> two 16-bit units instead */
					undo = true;
				} else if ((d.op->flags & USIP_F_ADJDEF) && dist < 2) {
					/* R-st1h: the F' = 0 st.h tail is deferred (+2 or farther); at +1 the pair is undone */
					undo = true;
				} else if ((d.op->flags & USIP_F_ADJ2) && dist != 2) {
					if ((d.op->kind == USIP_K_LOOP && dist < 2 && Fp == 1) || d.op->kind == USIP_K_LD || d.op->kind == USIP_K_ST) {
						/* loop #N with F = 1 and an ADJACENT S = 0 tail: two 16-bit ops; R-op1fs: the F != S ld.b / st.h of op 1
						 * only at +2 (undone elsewhere) */
						undo = true;
					} else {
						/* control tail with F' = 0 (or the S0F1 tail): valid EXACTLY at +2; R-loopA: the F' = 0 loop tail at +1 or
						 * farther is .word too */
						make_word (&d);
					}
				} else if ((d.op->flags & USIP_F_ADJCTRL) && is_ctrl_kind (d.op->kind)
					&& (dist > 2 || (S == 1 && dist > 1 && !(d.op->kind == USIP_K_LOOP && Fp == 0)))) {
					/* (a loop with an F' = 0 tail accepts S = 1 at +2: loop_F0, loop.b1?) */
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
			if ((undo || d.kind == USIP_K_OTHER) && (h & 0xF) == 0 && (h >> 15) == 0 && dist == 2 && Fp == 0
				&& (((t >> 12) & 3) == 1 || ((t >> 12) & 3) == 2)) {
				/* R-hhttF0 / R-F0d (the f0ctx context entries, in table order): the op 0 + [S][0][01|10] pair at +2 that the table
				 * reads .word is ld.h? / ld.hu? when it is the second head of an H H T T with a named first ld/st pair, or when the
				 * head has base sp and the adjacent unit is head-shaped */
				const ut64 w = ((ut64)h << 16) | t;
				for (j = 0; j < N_OPS; j++) {
					const UsipOpcode *f = &usip_opcodes[j];
					if (!(f->flags & USIP_F_F0CTX) || f->nunits != 2 || (w & f->mask) != f->value) {
						continue;
					}
					if (f->ncons && !cons_ok (f, w, first, &ctxd, CM_FREE | CM_DEFER)) {
						continue;
					}
					memset (&d, 0, sizeof (d));
					d.nt = 1;
					d.w = w;
					set_form (&d, f, pc);
					undo = false;
					break;
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
			CtxD ctxd = CTXD_INIT (c->n, k, units, i);
			ctxd.tail_idx = asg->t[m][0];
			d = dec48 (c->guard, pc, h, units[asg->t[m][0]], units[asg->t[m][1]], first, &ctxd);
			d.t[0] = asg->t[m][0];
			d.t[1] = asg->t[m][1];
		}
		d.head = i;
		out->d[out->n++] = d;
	}
	/* R-F0d (context rule f0d_middle_unit, text only): the unit between an rf0d_* head and its deferred tail, decoded as a
	 * 16-bit op without tail, is re-read with the first-slot 16-bit cell and keeps that reading only when named, not control
	 * and not a write of r14 */
	for (m = 0; m < out->n; m++) {
		Dec *d = &out->d[m];
		bool prev_rf0d = false;
		if (d->nt) {
			continue;
		}
		for (j = 0; j < out->n; j++) {
			prev_rf0d |= out->d[j].head + 1 == d->head && is_rf0d (&out->d[j]);
		}
		if (!prev_rf0d) {
			continue;
		}
		const ut64 pc = c->addrs[d->head];
		Dec d2 = dec16 (c->guard, pc, units[d->head], true, c->n, kidx (c, pc));
		if (strcmp (d2.mnem, d->mnem) && is_named (&d2) && !is_ctrl_any (d2.kind) && !first_operand_is (&d2, pc, "r14", ", \t")) {
			/* rf0dmidwaw: the re-read middle unit is not renamed when its destination is written by another instruction of the
			 * packet */
			const int dst = dec_dst (&d2, pc, false);
			bool twice = false;
			for (j = 0; dst >= 0 && j < out->n && !twice; j++) {
				twice = j != m && dec_dst (&out->d[j], c->addrs[out->d[j].head], false) == dst;
			}
			if (twice) {
				continue;
			}
			d2.head = d->head;
			*d = d2;
		}
	}
}

/* ---------------------------------------------------------------------------------------------------- scoring */

/* lr32: true while the rest of a 48-bit call.abs / b.abs packet is parsed (a mov32 r15, #return in its delay slot) */
static bool g_lr32 = false;

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

/* kinds of the 16-bit ops with a destination (the identical-units rule of 4-unit packets, the nowaw step) */
static bool waw_kind(int kind) {
	switch (kind) {
	case USIP_K_ALU: case USIP_K_ALU32: case USIP_K_MOV: case USIP_K_MOVI: case USIP_K_MOVI21: case USIP_K_LD: case USIP_K_DSP:
	case USIP_K_MUL: case USIP_K_MOV32: case USIP_K_MOVI32: case USIP_K_MEM16: case USIP_K_BIT: case USIP_K_DSPACC: case USIP_K_CSR:
	case USIP_K_IO:
		return true;
	}
	return false;
}

/* every other instruction of the reading is named and none of their mnemonics ends in ? (ctx rest_named_no_q, R-slotm1) */
static bool rest_named_no_q(const DecList *dec) {
	int k;
	for (k = 1; k < dec->n; k++) {
		if (!is_named (&dec->d[k]) || strchr (dec->d[k].mnem, '?')) {
			return false;
		}
	}
	return true;
}

/* rule R7: the context form of a bare first-slot unit (bit 15 = 0) read as .hword when the rest of the packet is
 * named: ldslot_S0 / stslot_S0 (slot family), their m = 1 twins ldslot_S0_m1 / stslot_S0_m1 (R-slotm1: the rest of the
 * packet also without a ? mnemonic) or lea_sp_S0 (when no other instruction of the packet has a tail), in table order */
static const UsipOpcode *r7_form(ut16 u, const DecList *dec) {
	static const int forms[5] = { USIP_FORM_LEA_SP_S0, USIP_FORM_LDSLOT_S0, USIP_FORM_STSLOT_S0, USIP_FORM_LDSLOT_S0_M1, USIP_FORM_STSLOT_S0_M1 };
	int order[5], n = 0, i, k;
	for (i = 0; i < 5; i++) {
		for (k = n; k > 0 && forms[order[k - 1]] > forms[i]; k--) {
			order[k] = order[k - 1];
		}
		order[k] = i;
		n++;
	}
	for (k = 0; k < 5; k++) {
		i = order[k];
		const UsipOpcode *f = &usip_opcodes[forms[i]];
		if ((u & f->mask) != f->value || (f->ncons && !cons_ok (f, u, true, NULL, CM_FREE | CM_DEFER))) {
			continue;
		}
		bool ctx_ok = true;
		int q;
		for (q = 0; q < f->ncons; q++) {
			if (f->cons[q].op == USIP_C_CTX && f->cons[q].vals[0] == USIP_CTX_REST_NAMED_NO_Q) {
				ctx_ok &= rest_named_no_q (dec);
			}
		}
		if (!ctx_ok) {
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

/* P2W: is the reading H H T T (4 units) or H H T T C (5 units with a 16-bit closer without tail)?  op 0/1 heads at
 * units 0 and 1 with their tails at 2 and 3 */
static bool hhtt_layout(const Ctx *c, const DecList *dec) {
	const int n = c->n;
	int i, t0 = -1, t1 = -1, nt4 = -1;
	if ((n != 4 && n != 5) || (c->units[0] & 0xE) || (c->units[1] & 0xE)) {
		return false;
	}
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		if (d->head == 0) {
			t0 = d->nt == 1? d->t[0]: -2;
		} else if (d->head == 1) {
			t1 = d->nt == 1? d->t[0]: -2;
		} else if (d->head == 4) {
			nt4 = d->nt;
		}
	}
	if (t0 != 2 || t1 != 3) {
		return false;
	}
	return n == 4 || (dec->n == 3 && nt4 == 0);
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
	const UsipGuardCtx *g = c->guard;
	Score s = { 0 };
	int unnamed = 0, pen = 0, i, j, hhtt = -1;
	ut8 tails_of7 = 0;
	decode_asg (c, asg, first_ok, dec);
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		const ut16 hu = units[d->head];
		if ((hu & 0xF) == 7 && d->nt) {
			tails_of7 |= 1 << d->t[0];
		}
		if (d->kind == USIP_K_OTHER) {
			unnamed += 1 + d->nt;
		} else if (d->kind == USIP_K_FMT) {
			unnamed += 1;
			if (!strcmp (d->mnem, ".hi") || !strcmp (d->mnem, ".hilo")) {
				pen += Q (0.25);
			}
		} else if (d->nt == 2 && mn_in_fam48 (d->mnem) && is_hi1010 (units[d->t[0]]) && (((hu >> 4) & 0xF) == 14 || ((hu >> 4) & 0xF) == 15)) {
			pen += Q (0.5);
		} else if ((d->kind == USIP_K_LD || d->kind == USIP_K_ST) && d->nt == 1 && !((hu & 0xF) == 4 && ((units[d->t[0]] >> 12) & 3) == 2)) {
			/* alignment: ld.w/st.w(?) with f12 not a multiple of 4 (except the closed R-off.w band f12 = 3 mod 4 >= 0xf00 and,
			 * in the H H T T / H H T T C layout, the W14 class f12 = 2 mod 4: P2W), ld.h/st.h with an odd f12 */
			const int off = units[d->t[0]] & 0xFFF, r4 = off & 3;
			const bool w = ends_with (d->mnem, ".w") || ends_with (d->mnem, ".w?");
			bool bad_w = r4 != 0 && !(r4 == 3 && off >= 0xF00);
			bool odd_h = ends_with (d->mnem, ".h") && (off & 1);
			if (bad_w && r4 == 2) {
				/* P2W: the = 2 class is exempt in H H T T / H H T T C and when H H T T is the prefix of a >= 5-unit packet */
				if (hhtt < 0) {
					hhtt = (hhtt_layout (c, dec) || hhtt_prefix_dec (c, dec))? 1: 0;
				}
				bad_w = !hhtt;
			}
			if (odd_h) {
				/* P2H: the odd half-word offset (negative by R-off.h) is not penalised in H H T T / H H T T C (or the H H T T
				 * prefix), except f12 = 0x001 with base sp */
				if (hhtt < 0) {
					hhtt = (hhtt_layout (c, dec) || hhtt_prefix_dec (c, dec))? 1: 0;
				}
				if (hhtt && !(off == 0x001 && (hu & 0x3E00) == 0x1C00)) {
					odd_h = false;
				}
			}
			if ((w && bad_w) || odd_h) {
				pen += Q (0.5);
				if (w && bad_w && (r4 == 1 || r4 == 3)) {
					/* al1: the = 1 / = 3 (< 0xf00) word tails pay 0.8 in all, above a double write (0.75) */
					pen += Q (0.3);
				}
			}
		}
		if (d->nt == 2 && is_hi1010 (units[d->t[0]])) {
			/* R-align48: a formed 48-bit ld/st trio of the hi(1010) family whose address is misaligned */
			const int align = (!strcmp (d->mnem, "ld.w") || !strcmp (d->mnem, "st.w"))? 4:
				(!strcmp (d->mnem, "ld.h") || !strcmp (d->mnem, "ld.hu") || !strcmp (d->mnem, "st.h"))? 2: 0;
			const ut32 a48 = 0x78000000U | ((ut32)(units[d->t[0]] & 0x1FFF) << 14) | (units[d->t[1]] & 0x3FFF);
			if (align && (a48 % align)) {
				pen += Q (0.5);
			}
		}
		if (n == 2 && !d->nt && d->kind == USIP_K_MEM16 && (!strcmp (d->mnem, "ld.b") || !strcmp (d->mnem, "ld.bu") || !strcmp (d->mnem, "ld.h")
			|| !strcmp (d->mnem, "st.b") || !strcmp (d->mnem, "st.bu") || !strcmp (d->mnem, "st.h")) && first_operand_is (d, c->addrs[d->head], "r15", ",")) {
			/* R-lr16 (2-unit packets only): a 16-bit ld/st.b|bu|h r15, [rA] is a [S][F'][tt][f12] tail read as a 16-bit op */
			pen += Q (0.5);
		}
		if (d->kind == USIP_K_CALL && d->has_target && g && g->inside_function && g->inside_function (g->user, d->target) == 1) {
			/* callin: a relative call whose target lies strictly inside a known function pays as an out-of-boundary target */
			pen += Q (1.5);
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
	{
		/* R-c48sym: a family head left without tails while a later free hi(1010) (16-bit op or head of a pair) + lo encode an
		 * address already formed elsewhere: +0.5 */
		ut32 tails_all = 0;
		for (i = 0; i < dec->n; i++) {
			for (j = 0; j < dec->d[i].nt; j++) {
				tails_all |= 1U << dec->d[i].t[j];
			}
		}
		for (i = 0; i < dec->n; i++) {
			const Dec *d = &dec->d[i];
			if (d->nt || !fam_head (units[d->head])) {
				continue;
			}
			for (j = d->head + 1; j + 1 < n; j++) {
				if (!is_hi1010 (units[j]) || ((tails_all >> j) & 1)) {
					continue;
				}
				if (((tails_all >> (j + 1)) & 1) && !formed (dec, j, 1, j + 1, 0)) {
					continue;
				}
				if (c48sym_has (0x78000000U | ((ut32)(units[j] & 0x1FFF) << 14) | (units[j + 1] & 0x3FFF))) {
					pen += Q (0.5);
					break;
				}
			}
		}
	}
	if (n == 4 && !(units[0] >> 15) && !(units[1] >> 15) && (units[0] & 0xF) == 0xC && (units[1] & 0xF) == 0xC
		&& ((units[2] >> 12) & 3) == 0 && ((units[3] >> 12) & 3) == 0 && ((units[2] >> 4) & 0xFF) == 0x8C && ((units[3] >> 4) & 0xFF) == 0x8C
		&& !(dec->n == 2 && formed (dec, 0, 1, 2, 0) && formed (dec, 1, 1, 3, 0))) {
		/* sat40 H H T T: [op c][op c][tail (8,c)][tail (8,c)] not read as the pairs 0 -> 2, 1 -> 3: +3.0 */
		pen += Q (3.0);
	}
	{
		/* R-waw: every register written by >= 2 instructions of the reading pays 0.75 (stores excluded by mnemonic; the pair
		 * [movi rA][16-bit op 2 rA, x = 1] of the same rrr, adjacent and both bare, is one instruction and does not count);
		 * rf0dpen: +1.0 for the bare unit after an R-F0d head when its destination is written twice in the reading;
		 * R-bsnext: +2.5 for a 16-bit b.s in the first slot whose target is exactly the next packet and not a function start */
		int cnt[32] = { 0 }, cnt_all[32] = { 0 }, dst[NU];
		bool rf0d_head[NU] = { false };
		for (i = 0; i < dec->n; i++) {
			const Dec *d = &dec->d[i];
			const int hi = d->head;
			dst[i] = dec_dst (d, c->addrs[hi], false);
			if (dst[i] >= 0) {
				cnt_all[dst[i]]++;
			}
			if (!strcmp (d->mnem, "iow")) {
				dst[i] = -1;
			}
			if (d->nt && is_rf0d (d)) {
				rf0d_head[hi] = true;
			}
			if (!d->nt && hi >= 1 && (units[hi] & 0x300F) == 0x0002 && ((units[hi] >> 8) & 1) == 1 && (units[hi - 1] & 0xE00F) == 0x0007
				&& ((units[hi - 1] >> 8) & 1) == 0 && ((units[hi] >> 9) & 7) == ((units[hi - 1] >> 9) & 7)) {
				for (j = 0; j < dec->n; j++) {
					if (dec->d[j].head == hi - 1 && !dec->d[j].nt && !strcmp (dec->d[j].mnem, "movi")) {
						break;
					}
				}
				if (j < dec->n) {
					continue;
				}
			}
			if (dst[i] >= 0) {
				cnt[dst[i]]++;
			}
		}
		for (j = 0; j < 32; j++) {
			if (cnt[j] >= 2) {
				pen += Q (0.75);
			}
		}
		for (i = 0; i < dec->n; i++) {
			const Dec *d = &dec->d[i];
			if (!d->nt && d->head >= 1 && rf0d_head[d->head - 1] && dst[i] >= 0 && cnt_all[dst[i]] >= 2) {
				pen += Q (1.0);
			}
			if (d->nt == 1 && d->op && !strncmp (d->op->form, "rf0dall", 7) && dst[i] >= 0 && cnt_all[dst[i]] >= 2) {
				/* rf0dall nowaw: the F' = 0 half-word load with a base other than sp pays when another instruction of the reading
				 * writes its destination */
				pen += Q (1.0);
			}
		}
		if (first_ok && dec->n && dec->d[0].head == 0 && dec->d[0].kind == USIP_K_BR16D && !strcmp (dec->d[0].mnem, "b.s") && dec->d[0].has_target
			&& dec->d[0].target == ((c->addrs[0] + 2 * (ut64)n) & UT32_MAX)
			&& !(g && g->function_start && g->function_start (g->user, dec->d[0].target) == 1)) {
			pen += Q (2.5);
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
	{
		/* the score rules lr32 (a mov32 r15, #X with X a packet start of the same function inside a reading with a jump / call,
		 * or in the rest of a call.abs / b.abs packet, scores like a validated target: a manual link), spodd (a 16-bit addi r14, #imm
		 * whose imm is not a multiple of 4 pays 1.0: an impossible sp move), rr7 (a movi rB, #imm17 formed while an earlier op 7 head
		 * of the reading with x = 0 and no tail stays bare pays 0.25: the null-field tail goes to the FIRST tail-less op 7 head) */
		bool has_jump = g_lr32;
		for (i = 0; i < dec->n && !has_jump; i++) {
			const int kd = dec->d[i].kind;
			has_jump = kd == USIP_K_BR || kd == USIP_K_BR16 || kd == USIP_K_BR16D || kd == USIP_K_JUMPA || kd == USIP_K_CALL || kd == USIP_K_CALLA || kd == USIP_K_CALL16;
		}
		for (i = 0; i < dec->n; i++) {
			const Dec *d = &dec->d[i];
			const ut64 pc = c->addrs[d->head];
			bool ok = false;
			if (has_jump && !strcmp (d->mnem, "mov32") && first_operand_is (d, pc, "r15", ",")) {
				const st64 v = text_imm (d, pc, &ok);
				if (ok && v >= 0 && g && g->packet_start && g->packet_start (g->user, (ut64)v & UT32_MAX) == 1) {
					pen -= Q (1.0);
				}
			}
			if (!d->nt && !strcmp (d->mnem, "addi") && first_operand_is (d, pc, "r14", ",")) {
				const st64 v = text_imm (d, pc, &ok);
				if (ok && (v % 4) != 0) {
					pen += Q (1.0);
				}
			}
			if (d->nt == 1 && !strcmp (d->mnem, "movi") && (units[d->head] & 0xF) == 7 && (units[d->t[0]] & 0x3FF0) == 0
				&& ((units[d->t[0]] & 0xF) == 1 || (units[d->t[0]] & 0xF) == 3)) {
				for (j = 0; j < dec->n; j++) {
					const Dec *e = &dec->d[j];
					if (e->head < d->head && !e->nt && (units[e->head] >> 15) == 0 && (units[e->head] & 0x10F) == 0x007) {
						pen += Q (0.25);
						break;
					}
				}
			}
		}
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
		CtxD ctxd = CTXD_INIT (c->n, kidx (c, c->addrs[i]), units, i);
		ctxd.tail_dist = 1;
		ctxd.tail_idx = i + 1;
		Dec d = dec32 (c->guard, c->addrs[i], h, units[i + 1], first, &ctxd, false, false, 1, &st);
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

/* guard not_over_validated_call32 (R-bcc48d22): the 64-bit b<cond>.l with a free extension unit X is not taken when U0 + X, read
 * as an adjacent 32-bit pair in the first slot, are a call / b whose target is a function start.  Function starts are what the
 * caller knows: with the function_start callback the test is exact; without it a target the caller validated as a
 * packet start (a function start decoded earlier in the session, or a local packet start) stands in. */
static bool over_validated_call32(const Ctx *c) {
	CtxD ctxd = CTXD_INIT (-1, 0, NULL, 0);
	int st;
	ut8 gd = USIP_G_NONE;
	ctxd.tail_dist = 1;
	ctxd.tail_idx = 1;
	const UsipOpcode *f = resolve32 (c->guard, c->units[0], c->units[1], true, &ctxd, false, false, c->addrs[0], 1, &st, &gd);
	if (!f || st != RS_OK) {
		return false;
	}
	if (f->kind != USIP_K_CALL && f->kind != USIP_K_CALLA && f->kind != USIP_K_CALL16 && f->kind != USIP_K_BR && f->kind != USIP_K_JUMPA) {
		return false;
	}
	bool has = false;
	const ut64 w = ((ut64)c->units[0] << 16) | c->units[1];
	const ut64 tg = target_value (f, w, c->addrs[0], &has);
	if (!has) {
		return false;
	}
	const UsipGuardCtx *g = c->guard;
	if (g && g->function_start) {
		return g->function_start (g->user, tg) == 1;
	}
	return gd == USIP_G_OK || (g && g->packet_start && g->packet_start (g->user, tg) == 1);
}

/* the packet-prefix forms (bcc48 / bcc64, and the 64-bit variant whose extension unit is any 16-bit unit X: *xvar): the first
 * one whose mask, context-free constraints and target guard(s) hold over the first nunits units; a failing guard = the form is
 * not taken */
static const UsipOpcode *match_prefix(const Ctx *c, ut64 *w_out, ut8 *guard, bool *xvar) {
	int i, k;
	*xvar = false;
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
		if (f->ncons && !cons_ok (f, w, true, NULL, CM_FREE)) {
			continue;
		}
		const int tg = tguard (f);
		if (tg) {
			bool has = false;
			const ut64 target = target_value (f, w, c->addrs[0], &has);
			const int st = has? eval_tguard (c->guard, f, tg, target, 0, w, c->addrs[0]): 0;
			if (!st) {
				continue;
			}
			*guard = st;
		} else {
			*guard = USIP_G_NONE;
		}
		if ((form_info (f) & FI_XGUARD) && over_validated_call32 (c)) {
			continue;
		}
		*xvar = f->nunits == 4 && ((f->mask >> 32) & 0xFFFF) == 0x8000;
		*w_out = w;
		return f;
	}
	return NULL;
}

static bool parse_packet(const UsipGuardCtx *g, const ut16 *units, const ut64 *addrs, int n, bool first_ok, ut64 pk0, DecList *best, TieList *ties);
static bool rest_parse(const Ctx *c, const int *rest, int nr, DecList *best, TieList *ties);

/* context rule bz_s_P5 (R-bzs5): a first-slot 4X?5/6X?5 unit (bit 15 = 0, bit 3 = 0, rA not sp/LR) whose best reading is a
 * bare unnamed unit is bz.s rA, dest with the rest of the packet as its delay slot: unconditionally in a 2-unit packet, in a
 * longer one only when the target is a packet start of the same function; the rest is parsed as an independent packet
 * without control flow (its ties replace the packet's for the cascade).  Returns true when the rule applied. */
static bool apply_bzs5(const Ctx *c, DecList *best, bool first_ok, TieList *ties, bool *amb) {
	const ut16 *units = c->units;
	const int n = c->n;
	int rest[NU], nr = 0, k;
	if (!first_ok || n < 2 || (units[0] & 0xC00F) != 0x4005 || (units[0] & 0x1E00) == 0x1C00 || (units[0] & 0x1E00) == 0x1E00) {
		return false;
	}
	if (!best->n || best->d[0].head != 0 || best->d[0].nt || is_named (&best->d[0])) {
		return false;
	}
	Dec d0 = { 0 };
	d0.w = units[0];
	set_form (&d0, &usip_opcodes[USIP_FORM_BZ_S_P5], c->addrs[0]);
	if (n != 2) {
		const UsipGuardCtx *g = c->guard;
		if (!d0.has_target || !g || !g->packet_start || g->packet_start (g->user, d0.target) != 1) {
			return false;
		}
		d0.guard = USIP_G_OK;
	}
	for (k = 1; k < n; k++) {
		rest[nr++] = k;
	}
	best->n = 0;
	best->d[best->n++] = d0;
	*amb = rest_parse (c, rest, nr, best, ties);
	return true;
}

/* parse the units after a prefix instruction (indices rest[0..nr)) as an independent packet without control flow; the
 * readings tied in that parse are remapped onto the whole packet (prefix instruction + rest) for the cascade */
static bool rest_parse(const Ctx *c, const int *rest, int nr, DecList *best, TieList *ties) {
	bool amb = false;
	int i, k, t;
	if (nr > 1) {
		ut16 ru[NU];
		ut64 ra[NU];
		DecList sub;
		TieList subties = { 0 };
		const int nprefix = best->n;
		for (k = 0; k < nr; k++) {
			ru[k] = c->units[rest[k]];
			ra[k] = c->addrs[rest[k]];
		}
		amb = parse_packet (c->guard, ru, ra, nr, false, c->pk0, &sub, ties? &subties: NULL);
		for (i = 0; i < sub.n; i++) {
			Dec d = sub.d[i];
			d.head = rest[d.head];
			for (k = 0; k < d.nt; k++) {
				d.t[k] = rest[d.t[k]];
			}
			best->d[best->n++] = d;
		}
		if (ties && subties.n) {
			ties->n = 0;
			ties->first_ok = false;
			for (t = 0; t < subties.n; t++) {
				DecList full = { .n = 0 };
				for (i = 0; i < nprefix; i++) {
					full.d[full.n++] = best->d[i];
				}
				for (i = 0; i < subties.d[t].n; i++) {
					Dec d = subties.d[t].d[i];
					d.head = rest[d.head];
					for (k = 0; k < d.nt; k++) {
						d.t[k] = rest[d.t[k]];
					}
					full.d[full.n++] = d;
				}
				qsort (full.d, full.n, sizeof (Dec), dec_cmp_head);
				tielist_push (ties, &full);
			}
		}
		tielist_fini (&subties);
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

/* the rule that produces an F-slot0 reading (ln_stslot_f0): only the F = 0 head of a split .op4imm pair keeps the ? for k >= 16 */
enum { LN_SLOT4N = 0, LN_OP4IMM, LN_SLOTPAIR0, LN_FSLOT0C };

/* F-slot0: [S][0][m][h][rrr][x][B][o3 100] = stslot rB(!x), #k (k = m:h:rrr:o3): stslot_F0 (k < 16), stslot_F0_k16 (k >= 16: h or
 * m = 1; R-slot4n, slotpair0, R-fslot0c, the R-slotc tails) or stslot_F0_q for the F = 0 head of a split .op4imm pair with k >= 16
 * or in a multi-unit packet (stslot16) */
static Dec ln_stslot_f0(const Ctx *c, int j, int rule, bool multi_op4imm) {
	Dec d = { 0 };
	const ut16 u = c->units[j];
	int idx;
	d.w = u;
	if (rule == LN_OP4IMM && ((u & 0x3000) || multi_op4imm)) {
		idx = USIP_FORM_STSLOT_F0_Q;
	} else {
		idx = (u & 0x3000)? USIP_FORM_STSLOT_F0_K16: USIP_FORM_STSLOT_F0;
	}
	set_form (&d, &usip_opcodes[idx], c->addrs[j]);
	d.head = j;
	return d;
}

/* S0-slot: a slot-family unit with F = 1 and S = 0 (low 12 bits > 1) = stslot rB, #k (o2 = 1) / ldslot rB, #k (o2 = 0; without the ?
 * since the 760-form table: ldslotk1) */
static Dec ln_slot_f1(const Ctx *c, int j) {
	Dec d = { 0 };
	const ut16 u = c->units[j];
	d.w = u;
	set_form (&d, &usip_opcodes[((u >> 2) & 1)? USIP_FORM_STSLOT_S0_POS1: USIP_FORM_LDSLOT_S0_POS1], c->addrs[j]);
	d.head = j;
	return d;
}

/* the unit is a slot-family unit with F = 1, S = 0, low 12 bits > 1 and (m = 0 or op != 0) */
static inline bool slot_f1_shape(ut16 u) {
	return (u & 0xC003) == 0x4000 && (u & 0x0FFF) > 1 && ((u & 0x2000) == 0 || (u & 0xC) != 0);
}

/* the split-tail reading of unit j: the slot family with F = 1 and S = 0 (S0-slot), op 4 / op c with F = 0 (F-slot0), else the
 * ordinary 16-bit reading in tail position; *named = it has a name */
static Dec ln_tail16(const Ctx *c, int j, int rule, bool *named) {
	const ut16 t = c->units[j];
	*named = true;
	if (slot_f1_shape (t)) {
		return ln_slot_f1 (c, j);
	}
	if ((t & 0x4007) == 0x0004) {
		return ln_stslot_f0 (c, j, rule, false);
	}
	Dec d = dec16 (c->guard, c->addrs[j], t, false, c->n, kidx (c, c->addrs[j]));
	d.head = j;
	*named = is_named (&d);
	return d;
}

/* the post-layout splits and renames of the slot family (names only, the layout is untouched): R-slot4n (a pair read
 * .op4t0 / .op4t1 / .op4t3 with an op 4 F = 0 head and the adjacent S = 0 tail -> stslot (F-slot0) || the tail's 16-bit
 * reading), R-op4imm (a pair read .op4imm whose F' = 0 tail has a named 16-bit reading -> stslot / stslot? || the tail),
 * S0-slot (a bare .hword of the slot family with F = 1 and S = 0 at INSTRUCTION position 1 -> stslot / ldslot?); then the
 * nowaw guardian: a new reading whose destination is written by another instruction of the packet returns its original
 * entry whole */
static void ln_rename(const Ctx *c, DecList *best) {
	const ut16 *units = c->units;
	const int n = c->n;
	Dec out[2 * NU];
	int orig[2 * NU], nout = 0, kpos, i, j;
	bool changed = false;
	for (kpos = 0; kpos < best->n; kpos++) {
		const Dec *d = &best->d[kpos];
		const ut16 h = units[d->head];
		if (d->nt == 1) {
			const int ti = d->t[0];
			const ut16 t = units[ti];
			if ((!strcmp (d->mnem, ".op4t0") || !strcmp (d->mnem, ".op4t1") || !strcmp (d->mnem, ".op4t3")) && ti == d->head + 1
				&& (h & 0xC00F) == 0x0004 && (t >> 15) == 0 && (t & 0x0FFF) > 1 && (t & 0x7BFF) != 0x4000) {
				bool named;
				out[nout] = ln_stslot_f0 (c, d->head, LN_SLOT4N, false);
				orig[nout++] = kpos;
				out[nout] = ln_tail16 (c, ti, LN_SLOT4N, &named);
				orig[nout++] = kpos;
				changed = true;
				continue;
			}
			if (!strcmp (d->mnem, ".op4imm") && (h & 0x800F) == 0x0004 && (t & 0x6000) == 0) {
				bool named;
				const Dec d2 = ln_tail16 (c, ti, LN_OP4IMM, &named);
				if (named) {
					out[nout] = ((h >> 14) & 1)? ln_slot_f1 (c, d->head): ln_stslot_f0 (c, d->head, LN_OP4IMM, n > 2);
					orig[nout++] = kpos;
					out[nout] = d2;
					orig[nout++] = kpos;
					changed = true;
					continue;
				}
			}
			if ((h & 0xC00F) == 0x000C && slotc_ok (h, t, d)) {
				/* R-slotc (the table's post-layout split (7)): an op c head with F = 0 and its single tail with tt = 00 and rd in {4, c}
				 * read without a firm name are a slot pair: head stslot rB(x), #m:h:rrr:1 || tail stslot rX, #k (the ? twins when no call
				 * follows within two packets: slotc_mark) */
				Dec a = { 0 }, b = { 0 };
				a.w = h;
				set_form (&a, &usip_opcodes[USIP_FORM_STSLOT_SLOTC_H], c->addrs[d->head]);
				a.head = d->head;
				b.w = t;
				set_form (&b, &usip_opcodes[USIP_FORM_STSLOT_SLOTC_T], c->addrs[ti]);
				b.head = ti;
				out[nout] = a;
				orig[nout++] = kpos;
				out[nout] = b;
				orig[nout++] = kpos;
				changed = true;
				continue;
			}
		} else if (!d->nt && !strcmp (d->mnem, ".hword") && kpos == 1 && slot_f1_shape (h)) {
			out[nout] = ln_slot_f1 (c, d->head);
			orig[nout++] = kpos;
			changed = true;
			continue;
		}
		out[nout] = *d;
		orig[nout++] = -1;
	}
	if (!changed) {
		return;
	}
	/* the nowaw guardian */
	int cnt[32] = { 0 }, dst[2 * NU];
	bool revert[NU] = { false };
	for (i = 0; i < nout; i++) {
		dst[i] = dec_dst (&out[i], c->addrs[out[i].head], true);
		if (dst[i] >= 0) {
			cnt[dst[i]]++;
		}
	}
	for (i = 0; i < nout; i++) {
		if (orig[i] >= 0 && dst[i] >= 0 && cnt[dst[i]] >= 2) {
			revert[orig[i]] = true;
		}
	}
	DecList res;
	res.n = 0;
	for (i = 0; i < nout; i++) {
		if (orig[i] < 0) {
			res.d[res.n++] = out[i];
		} else if (revert[orig[i]]) {
			for (j = 0; j < res.n && res.d[j].head != best->d[orig[i]].head; j++) {
				;
			}
			if (j == res.n) {
				res.d[res.n++] = best->d[orig[i]];
			}
		} else {
			res.d[res.n++] = out[i];
		}
	}
	qsort (res.d, res.n, sizeof (Dec), dec_cmp_head);
	*best = res;
}

/* the post rules on the final reading of a packet (hw_rules; applied before the split pass of ln_rename
 * and also after the b<cond>.l / call.abs prefix paths): R-add2 (the fusion at distance 2 of the table, entry add2_rot12: a bare
 * .hword head [0][0][m][h][rrr][x][B][0000] at unit i of a packet of >= 3 units and a bare UNNAMED closer [1][1][00][f12 = 0 mod 4]
 * at unit i + 2 become one add rB(!x), rA(!m), #rot12, unless another instruction of the packet already writes rB; the head must
 * read .hword: a bare m = h = 0 unit of the group parse is relabelled .ext, like the .ext entries of the table, and never
 * fuses) and R-fslot0c (a bare .hword / .ext F-slot0 unit [0][0][0][0][rrr][x][B][o3 100], low 12 bits > 1, at unit 1 of a packet
 * whose instruction 0 is a call / call.abs / callr / call16 is stslot: a frame store in the delay slot) */
static void hw_rules(const Ctx *c, DecList *best, bool first_ok) {
	const ut16 *units = c->units;
	const int n = c->n;
	int q, j;
	if (n >= 3) {
		int own[NU], cnt[32] = { 0 };
		bool removed[NU] = { false }, changed = false;
		for (j = 0; j < NU; j++) {
			own[j] = -1;
		}
		for (q = 0; q < best->n; q++) {
			const Dec *d = &best->d[q];
			const int dst = dec_dst (d, c->addrs[d->head], true);
			own[d->head] = q;
			for (j = 0; j < d->nt; j++) {
				own[d->t[j]] = q;
			}
			if (dst >= 0) {
				cnt[dst]++;
			}
		}
		for (q = 0; q < best->n; q++) {
			Dec *d = &best->d[q];
			const int i = d->head;
			if (removed[q] || d->nt || strcmp (d->mnem, ".hword") || (units[i] >> 15) || (units[i] & 0xF) != 0 || ((units[i] >> 14) & 1) || i + 2 >= n) {
				continue;
			}
			const int qt = own[i + 2];
			if (qt < 0 || qt == q || removed[qt]) {
				continue;
			}
			const Dec *e = &best->d[qt];
			const ut16 t = units[i + 2];
			if (!((t >> 12) == 0xC && (t & 3) == 0 && !e->nt && e->head == i + 2 && !is_named (e))) {
				continue;
			}
			const UsipOpcode *fa = &usip_opcodes[USIP_FORM_ADD2_ROT12];
			const ut64 w = ((ut64)units[i] << 16) | t;
			if ((w & fa->mask) != fa->value) {
				continue;
			}
			const int fb = field_index (fa, "rB"), fx = field_index (fa, "x");
			const int rb = (fb >= 0? (int)(field_value (fa, fb, w) & 15): 0) + ((fx >= 0 && field_value (fa, fx, w))? 16: 0);
			if (cnt[rb] >= 1) {
				/* nowaw: another instruction of the packet already writes rB */
				continue;
			}
			Dec nd = { 0 };
			nd.head = i;
			nd.nt = 1;
			nd.t[0] = i + 2;
			nd.w = w;
			set_form (&nd, fa, c->addrs[i]);
			nd.has_target = false;
			*d = nd;
			removed[qt] = true;
			cnt[rb]++;
			changed = true;
		}
		if (changed) {
			DecList res;
			res.n = 0;
			for (q = 0; q < best->n; q++) {
				if (!removed[q]) {
					res.d[res.n++] = best->d[q];
				}
			}
			qsort (res.d, res.n, sizeof (Dec), dec_cmp_head);
			*best = res;
		}
	}
	if (n >= 3 && first_ok && best->n && best->d[0].head == 0
		&& (best->d[0].kind == USIP_K_CALL || best->d[0].kind == USIP_K_CALLA || best->d[0].kind == USIP_K_CALLR || best->d[0].kind == USIP_K_CALL16)) {
		for (q = 0; q < best->n; q++) {
			Dec *d = &best->d[q];
			if (d->nt || d->head != 1 || (strcmp (d->mnem, ".hword") && strcmp (d->mnem, ".ext"))) {
				continue;
			}
			const ut16 u = units[1];
			if ((u & 0xF007) != 0x0004 || (u & 0xFFF) <= 1) {
				continue;
			}
			*d = ln_stslot_f0 (c, 1, LN_FSLOT0C, false);
		}
	}
}

/* the packet-level context rules applied to the chosen reading (bz_s_P4, bz_s_P4_u4, bz_s_P4_F0, slot_S0_R7 / lea_sp_S0,
 * bz_s_P4_u3, S3, be79_prefix, the post rules R-add2 / R-fslot0c, the splits of the slot family); the bz.s rules re-parse the
 * rest of the packet as the delay slot (its ties replace the packet's for the cascade, as in apply_bzs5) */
static void post_rules(const Ctx *c, DecList *best, bool first_ok, TieList *ties, bool *amb) {
	const ut16 *units = c->units;
	const ut64 *addrs = c->addrs;
	const int n = c->n;
	const UsipGuardCtx *g = c->guard;
	const Ctx *saved_cur = g_cur;
	int k;
	g_cur = c;
	/* context rule bz_s_P4: a 2-unit packet opened by 4X?d/5X?d without a named reading */
	if (n == 2 && first_ok && (units[0] & 0xE00F) == 0x400D && units[0] != 0x5E0D && best->n && !is_named (&best->d[0])) {
		const UsipOpcode *f = &usip_opcodes[USIP_FORM_BZ_S_P4];
		const CtxD ctxd = CTXD_INIT (2, 0, NULL, 0);
		if ((units[0] & f->mask) == f->value && cons_ok (f, units[0], true, &ctxd, CM_FREE | CM_DEFER)) {
			Dec d0 = { 0 };
			d0.head = 0;
			d0.w = units[0];
			set_form (&d0, f, addrs[0]);
			Dec d1 = dec16 (c->guard, addrs[1], units[1], false, 2, kidx (c, addrs[1]));
			d1.head = 1;
			best->n = 0;
			best->d[best->n++] = d0;
			best->d[best->n++] = d1;
		}
	}
	/* context rule bz_s_P4_u4 (R-p4u4): the same 4X?d (not 5cXd / 5e0d, rA not sp) opening a packet of exactly 4 units whose
	 * best reading leaves it unnamed, with the target a packet start of the same function (d6 > 0): bz.s rA + the rest
	 * re-parsed as its delay slot */
	if (n == 4 && first_ok && (units[0] & 0xE00F) == 0x400D && units[0] != 0x5E0D && (units[0] & 0x1E00) != 0x1C00 && best->n
		&& best->d[0].head == 0 && !is_named (&best->d[0]) && ((units[0] >> 3) & 0x3F) > 0) {
		Dec d0 = { 0 };
		d0.w = units[0];
		set_form (&d0, &usip_opcodes[USIP_FORM_BZ_S_P4_U4], addrs[0]);
		if (d0.has_target && g && g->packet_start && g->packet_start (g->user, d0.target) == 1) {
			int rest[NU], nr = 0;
			d0.guard = USIP_G_OK;
			for (k = 1; k < n; k++) {
				rest[nr++] = k;
			}
			best->n = 0;
			best->d[best->n++] = d0;
			*amb = rest_parse (c, rest, nr, best, ties);
		}
	}
	/* context rule bz_s_P4_F0 (R-bzf0): the P4 cell with F = 0 (000h rrrd dddd d101, rA not sp) at k = 0 of a packet of exactly 2 or
	 * 3 units whose head has no named reading and is not the bare .hword op 5 x = 0 unit (the R-lsl0 cell), with d6 > 0 and the
	 * target a packet start of the same function beyond the packet: bz.s rA + the rest as its delay slot (at 2 units the second unit
	 * is a 16-bit op, at 3 the rest is re-parsed) */
	if ((n == 2 || n == 3) && first_ok && (units[0] & 0xE007) == 0x0005 && (units[0] & 0x1E00) != 0x1C00 && best->n && best->d[0].head == 0
		&& !is_named (&best->d[0]) && !((units[0] & 0x108) == 0 && !best->d[0].nt && !strcmp (best->d[0].mnem, ".hword"))) {
		Dec d0 = { 0 };
		d0.w = units[0];
		set_form (&d0, &usip_opcodes[USIP_FORM_BZ_S_P4_F0], addrs[0]);
		if (((units[0] >> 3) & 0x3F) > 0 && d0.has_target && d0.target >= addrs[n - 1] + 2 && g && g->packet_start && g->packet_start (g->user, d0.target) == 1) {
			d0.guard = USIP_G_OK;
			d0.head = 0;
			best->n = 0;
			best->d[best->n++] = d0;
			if (n == 2) {
				Dec d1 = dec16 (c->guard, addrs[1], units[1], false, 2, kidx (c, addrs[1]));
				d1.head = 1;
				best->d[best->n++] = d1;
				*amb = false;
			} else {
				const int rest[2] = { 1, 2 };
				*amb = rest_parse (c, rest, 2, best, ties);
			}
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
	/* context rule bz_s_P4_u3 (bzsd): 4X?d at k = 0 of a 3-unit packet, bare and unnamed, with the target a packet start of the
	 * same function BEYOND the packet and a re-parsed delay slot that does not write rA */
	if (n == 3 && first_ok && (units[0] & 0xE00F) == 0x400D && units[0] != 0x5E0D && (units[0] & 0x1E00) != 0x1C00 && best->n
		&& best->d[0].head == 0 && !best->d[0].nt && !is_named (&best->d[0])) {
		Dec d0 = { 0 };
		d0.w = units[0];
		set_form (&d0, &usip_opcodes[USIP_FORM_BZ_S_P4_U3], addrs[0]);
		if (d0.has_target && d0.target >= addrs[n - 1] + 2 && g && g->packet_start && g->packet_start (g->user, d0.target) == 1) {
			const int rA = (((units[0] >> 12) & 1) << 3) | ((units[0] >> 9) & 7);
			const int rest[2] = { 1, 2 };
			DecList tmp;
			TieList tt = { 0 };
			bool writes = false;
			d0.guard = USIP_G_OK;
			tmp.n = 0;
			tmp.d[tmp.n++] = d0;
			const bool amb3 = rest_parse (c, rest, 2, &tmp, ties? &tt: NULL);
			for (k = 1; k < tmp.n; k++) {
				writes |= dec_dst (&tmp.d[k], addrs[tmp.d[k].head], true) == rA;
			}
			if (!writes) {
				*best = tmp;
				*amb = amb3;
				if (ties && tt.n) {
					tielist_fini (ties);
					*ties = tt;
				} else {
					tielist_fini (&tt);
				}
			} else {
				tielist_fini (&tt);
			}
		}
	}
	if (n >= 2) {
		/* S3 (forms ldslot_S3_F0 / stslot_S3_F0): a bare .hword unit of the slot family with m = h = 1 and F = 0: in the first
		 * slot with S = 0 and o2 = 0 ldslot rB, #k (k = 48..63), as a closer with o2 = 1 stslot; before the split pass, no guardian */
		for (k = 0; k < best->n; k++) {
			Dec *d = &best->d[k];
			const ut16 u = units[d->head];
			if (d->nt || strcmp (d->mnem, ".hword") || (u & 0xFFF) <= 1 || (u & 3) != 0 || ((u >> 14) & 1) != 0 || ((u >> 12) & 3) != 3) {
				continue;
			}
			const int o2 = (u >> 2) & 1;
			if ((u >> 15) == 0 && d->head == 0 && o2 == 0) {
				const int hd = d->head;
				memset (d, 0, sizeof (*d));
				d->head = hd;
				d->w = u;
				set_form (d, &usip_opcodes[USIP_FORM_LDSLOT_S3_F0], addrs[hd]);
			} else if ((u >> 15) == 1 && o2 == 1) {
				const int hd = d->head;
				memset (d, 0, sizeof (*d));
				d->head = hd;
				d->w = u;
				set_form (d, &usip_opcodes[USIP_FORM_STSLOT_S3_F0], addrs[hd]);
			}
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
	if (n > 1) {
		hw_rules (c, best, first_ok);
		ln_rename (c, best);
	}
	g_cur = saved_cur;
}

/* the whole packet: the prefix forms, then every reading, scored with the layout order (s0, I, Fv, -A, K), then the
 * packet-level context rules (parse_packet).  Returns the ambiguity of the chosen reading; when ties
 * is given, the readings tied on (s0, I, Fv, -A) are stored there (distinct signatures, K order) for the cascade. */
static bool parse_packet_inner(Ctx *c, bool first_ok, DecList *best, TieList *ties);

static bool parse_packet(const UsipGuardCtx *g, const ut16 *units, const ut64 *addrs, int n, bool first_ok, ut64 pk0, DecList *best, TieList *ties) {
	/* R-b111: the packet (or delay-slot sub-packet) of exactly two units admits the b111 context forms in the grammar; the
	 * context of this parse is the one the R-w6h1 loop guard reads */
	const bool saved = g_ht2;
	const Ctx *saved_cur = g_cur;
	Ctx c = { 0 };
	c.units = units;
	c.n = n;
	c.pk0 = pk0;
	c.guard = g;
	memcpy (c.addrs, addrs, n * sizeof (ut64));
	g_ht2 = n == 2;
	g_cur = &c;
	const bool amb = parse_packet_inner (&c, first_ok, best, ties);
	g_ht2 = saved;
	g_cur = saved_cur;
	return amb;
}

static bool parse_packet_inner(Ctx *cp, bool first_ok, DecList *best, TieList *ties) {
	Ctx *c = cp;
	const UsipGuardCtx *g = c->guard;
	const ut16 *units = c->units;
	const ut64 *addrs = c->addrs;
	const int n = c->n;
	int i, k;
	best->n = 0;
	if (ties) {
		ties->n = 0;
		ties->first_ok = first_ok;
	}
	if (n == 1) {
		Dec d = dec16 (g, addrs[0], units[0], first_ok, 1, kidx (c, addrs[0]));
		d.head = 0;
		best->d[best->n++] = d;
		return false;
	}
	if (n == 2 && (units[0] & 0xC007) == 0x0004 && (units[0] & 0x0FFF) != 0 && (units[1] & 0xC007) == 0x8004 && (units[1] & 0x0FFF) != 0) {
		/* slotpair0 (the table's post-layout split (5), decided BEFORE the layout): a 2-unit packet of two F-slot0 units whose
		 * 32-bit reading has no name is stslot || stslot (never ambiguous) */
		CtxD ctxd = CTXD_INIT (n, 0, units, 0);
		int st;
		ctxd.tail_dist = 1;
		ctxd.tail_idx = 1;
		const Dec d32 = dec32 (g, addrs[0], units[0], units[1], first_ok, &ctxd, false, false, 1, &st);
		if (st == RS_UNDO || st == RS_WORD || !is_named (&d32)) {
			best->d[best->n++] = ln_stslot_f0 (c, 0, LN_SLOTPAIR0, false);
			best->d[best->n++] = ln_stslot_f0 (c, 1, LN_SLOTPAIR0, false);
			return false;
		}
	}
	if (first_ok && n >= 3) {
		ut64 w = 0;
		ut8 guard = USIP_G_NONE;
		int rest[NU], nr = 0, hi, lo;
		bool xvar = false, amb;
		const UsipOpcode *pf = match_prefix (c, &w, &guard, &xvar);
		if (pf) {
			/* b<cond>.l prefix: one instruction, the rest of the packet is its delay slot; the 64-bit variant with a free extension
			 * unit keeps the three units U0 U1 T and reads X on its own as the first 16-bit instruction of the delay slot */
			Dec d0 = { 0 };
			d0.head = 0;
			d0.w = w;
			d0.guard = guard;
			if (xvar) {
				d0.nt = 2;
				d0.t[0] = 2;
				d0.t[1] = 3;
			} else {
				d0.nt = pf->nunits - 1;
				for (k = 0; k < d0.nt; k++) {
					d0.t[k] = k + 1;
				}
			}
			set_form (&d0, pf, addrs[0]);
			best->d[best->n++] = d0;
			if (xvar) {
				Dec dx = dec16 (g, addrs[1], units[1], false, n, kidx (c, addrs[1]));
				dx.head = 1;
				best->d[best->n++] = dx;
			}
			for (k = pf->nunits; k < n; k++) {
				rest[nr++] = k;
			}
			amb = rest_parse (c, rest, nr, best, ties);
			hw_rules (c, best, first_ok);
			return amb;
		}
		if (abs_prefix (c, &hi, &lo)) {
			CtxD ctxd = CTXD_INIT (n, 0, units, 0);
			const bool saved_lr = g_lr32;
			ctxd.tail_idx = hi;
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
			/* lr32: the rest of a call.abs / b.abs packet contains a jump (a mov32 r15, #return in its delay slot scores like a
			 * validated target) */
			g_lr32 = true;
			amb = rest_parse (c, rest, nr, best, ties);
			g_lr32 = saved_lr;
			hw_rules (c, best, first_ok);
			return amb;
		}
	}
	const AsgList *all = group_parses (c, 0, first_ok);
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
		if (!unit_never_tail (units[2]) && !head_never_with_tail (units[0]) && match32 (units[0], units[2], true, false)) {
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
		&& (units[2] >> 15) == 0 && ((units[2] >> 14) & 1) == 1
		&& (units[3] >> 15) == 1 && ((units[3] >> 14) & 1) == 1 && units[2] != 0x5E0D && units[3] != 0x5E0D) {
		/* H H T T: the explicit candidate [h0][h1][t0 S=0][t1 S=1] with op 0/1 heads = two named ld/st in round-robin (R-b111:
		 * the tt = 11 tails, ld.bu / st.b, enter the candidate too) */
		Asg a = { 0 };
		DecList dd;
		a.n = 2;
		a.head[0] = 0;
		a.nt[0] = 1;
		a.t[0][0] = 2;
		a.head[1] = 1;
		a.nt[1] = 1;
		a.t[1][0] = 3;
		decode_asg (c, &a, first_ok, &dd);
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
	if (first_ok && n >= 5 && br_f0_head (units[0]) && (units[1] >> 15) == 0 && (units[1] & 0xE) == 0
		&& (units[2] >> 15) == 0 && ((units[2] >> 14) & 1) == 1 && (units[3] >> 15) == 0 && ((units[3] >> 14) & 1) == 1) {
		/* R-brHHTT: [branch F = 0 at 0 -> tail 2][ld/st at 1 -> tail 3] + the rest (units 4..) in packets of >= 5 units, when the
		 * branch reads with a validated target and the second pair reads ld/st (the b111 forms admitted); the same score decides */
		Asg a0 = { 0 };
		CtxD cd0 = CTXD_INIT (n, 0, units, 0), cd1 = CTXD_INIT (n, 1, units, 1);
		int st0, st1;
		a0.n = 2;
		a0.head[0] = 0; a0.nt[0] = 1; a0.t[0][0] = 2;
		a0.head[1] = 1; a0.nt[1] = 1; a0.t[1][0] = 3;
		cd0.tail_dist = cd1.tail_dist = 2;
		cd0.tail_idx = 2; cd1.tail_idx = 3;
		cd0.hh_asg = cd1.hh_asg = 1;
		const Dec dB0 = dec32 (g, addrs[0], units[0], units[2], first_ok, &cd0, false, false, 2, &st0);
		if (st0 == RS_OK && dB0.kind == USIP_K_BR && dB0.has_target && g && g->packet_start && g->packet_start (g->user, dB0.target) == 1) {
			const Dec dB1 = dec32 (g, addrs[1], units[1], units[3], false, &cd1, true, false, 2, &st1);
			if (st1 == RS_OK && (dB1.kind == USIP_K_LD || dB1.kind == USIP_K_ST)) {
				const AsgList *rest = group_parses (c, 4, false);
				const int nr = rest->n? rest->n: 1;
				for (i = 0; i < nr; i++) {
					Asg a = a0;
					if (rest->n) {
						const Asg *r = &rest->a[i];
						int m, q;
						for (m = 0; m < r->n; m++) {
							a.head[a.n] = r->head[m] + 4;
							a.nt[a.n] = r->nt[m];
							for (q = 0; q < r->nt[m]; q++) {
								a.t[a.n][q] = r->t[m][q] + 4;
							}
							a.n++;
						}
					}
					for (k = 0; k < seen.n && memcmp (&seen.a[k], &a, sizeof (Asg)); k++) {
						;
					}
					if (k == seen.n && !bad_assignment (c, &a)) {
						asglist_push (&seen, &a, 0);
					}
				}
			}
		}
	}
	if (first_ok && n >= 2 && (units[0] >> 15) == 0 && (units[0] & 0xF) == 0xF) {
		/* loopcand (R-loopA / R-loopB / R-loopM): the reading `loop #N` (op f head + tt = 10 tail at +1 / +2) is an explicit
		 * candidate, like the 3-unit [head][op16][F' = 0 tail] and H H T T: the group grammar drops it when the middle unit has no
		 * named 16-bit reading.  Only the readings `loop #N` (not `loop #N?`); the F' = 0 tail (R-loopA) only at +2. */
		int kk;
		for (kk = 1; kk <= 2; kk++) {
			if (kk >= n || ((units[kk] >> 12) & 3) != 2) {
				continue;
			}
			CtxD cd = CTXD_INIT (n, 0, units, 0);
			int st;
			cd.tail_dist = kk;
			cd.tail_idx = kk;
			const Dec dL = dec32 (g, addrs[0], units[0], units[kk], true, &cd, false, false, kk, &st);
			if (st != RS_OK || !dL.op || strcmp (dL.mnem, "loop#") || ((dL.op->flags & USIP_F_ADJ2) && kk != 2)) {
				continue;
			}
			Asg a0 = { 0 };
			a0.head[a0.n] = 0; a0.nt[a0.n] = 1; a0.t[a0.n][0] = kk; a0.n++;
			if (kk == 2) {
				a0.head[a0.n] = 1; a0.nt[a0.n] = 0; a0.n++;
			}
			const AsgList *rest = kk + 1 < n? group_parses (c, kk + 1, false): NULL;
			const int nr = rest? rest->n: 1;
			for (i = 0; i < nr; i++) {
				Asg a = a0;
				if (rest) {
					const Asg *r = &rest->a[i];
					int m, q;
					for (m = 0; m < r->n; m++) {
						a.head[a.n] = r->head[m] + kk + 1;
						a.nt[a.n] = r->nt[m];
						for (q = 0; q < r->nt[m]; q++) {
							a.t[a.n][q] = r->t[m][q] + kk + 1;
						}
						a.n++;
					}
				}
				for (k = 0; k < seen.n && memcmp (&seen.a[k], &a, sizeof (Asg)); k++) {
					;
				}
				if (k == seen.n && !bad_assignment (c, &a)) {
					asglist_push (&seen, &a, 0);
				}
			}
		}
	}
	if (first_ok && n >= 5 && (units[0] >> 15) == 0 && (units[1] >> 15) == 0 && (units[0] & 0xE) == 0 && (units[1] & 0xE) == 0
		&& (units[2] >> 15) == 0 && ((units[2] >> 14) & 1) == 1 && ((units[3] >> 14) & 1) == 1 && (((units[2] >> 12) & 3) == 3 || ((units[3] >> 12) & 3) == 3)) {
		/* R-b111pre: the H H T T of type 111 (st.b / ld.bu) as the PREFIX of a packet of >= 5 units, both tails S = 0; the rest
		 * of the packet is parsed as a group; the same score decides */
		Asg a0 = { 0 };
		CtxD cd0 = CTXD_INIT (n, 0, units, 0), cd1 = CTXD_INIT (n, 1, units, 1);
		int st0, st1;
		a0.n = 2;
		a0.head[0] = 0; a0.nt[0] = 1; a0.t[0][0] = 2;
		a0.head[1] = 1; a0.nt[1] = 1; a0.t[1][0] = 3;
		cd0.tail_dist = cd1.tail_dist = 2;
		cd0.tail_idx = 2; cd1.tail_idx = 3;
		cd0.hh_asg = cd1.hh_asg = 1;
		const Dec d0 = dec32 (g, addrs[0], units[0], units[2], first_ok, &cd0, true, false, 2, &st0);
		const Dec d1 = dec32 (g, addrs[1], units[1], units[3], false, &cd1, true, false, 2, &st1);
		if (st0 == RS_OK && st1 == RS_OK && (d0.kind == USIP_K_LD || d0.kind == USIP_K_ST) && (d1.kind == USIP_K_LD || d1.kind == USIP_K_ST)) {
			const AsgList *rest = group_parses (c, 4, false);
			for (i = 0; i < rest->n; i++) {
				Asg a = a0;
				const Asg *r = &rest->a[i];
				int m, q;
				for (m = 0; m < r->n; m++) {
					a.head[a.n] = r->head[m] + 4;
					a.nt[a.n] = r->nt[m];
					for (q = 0; q < r->nt[m]; q++) {
						a.t[a.n][q] = r->t[m][q] + 4;
					}
					a.n++;
				}
				for (k = 0; k < seen.n && memcmp (&seen.a[k], &a, sizeof (Asg)); k++) {
					;
				}
				if (k == seen.n && !bad_assignment (c, &a)) {
					asglist_push (&seen, &a, 0);
				}
			}
		}
	}
	if (first_ok && n == 4 && (units[0] >> 15) == 0 && (units[0] & 0xF) == 0xE && (units[1] >> 15) == 0 && (units[1] & 0xE) == 0
		&& (units[2] >> 15) == 0 && (((units[2] >> 12) & 7) == 6 || ((units[2] >> 12) & 7) == 7) && (units[3] >> 15) == 1) {
		/* R-b111ctl: the round-robin [b / call op e][op 1][S = 0 tag 6/7][S = 1 tt = 11] that the group grammar does not generate
		 * after a control head: the branch / call reads with a target and the second pair reads ld/st */
		Asg a0 = { 0 };
		CtxD cd0 = CTXD_INIT (n, 0, units, 0), cd1 = CTXD_INIT (n, 1, units, 1);
		int st0, st1;
		a0.n = 2;
		a0.head[0] = 0; a0.nt[0] = 1; a0.t[0][0] = 2;
		a0.head[1] = 1; a0.nt[1] = 1; a0.t[1][0] = 3;
		cd0.tail_dist = cd1.tail_dist = 2;
		cd0.tail_idx = 2; cd1.tail_idx = 3;
		cd0.hh_asg = cd1.hh_asg = 1;
		const Dec d0 = dec32 (g, addrs[0], units[0], units[2], first_ok, &cd0, false, false, 2, &st0);
		const Dec d1 = dec32 (g, addrs[1], units[1], units[3], false, &cd1, true, false, 2, &st1);
		if (st0 == RS_OK && (d0.kind == USIP_K_BR || d0.kind == USIP_K_CALL) && d0.has_target && st1 == RS_OK
			&& (d1.kind == USIP_K_LD || d1.kind == USIP_K_ST)) {
			for (k = 0; k < seen.n && memcmp (&seen.a[k], &a0, sizeof (Asg)); k++) {
				;
			}
			if (k == seen.n && !bad_assignment (c, &a0)) {
				asglist_push (&seen, &a0, 0);
			}
		}
	}
	bool amb;
	if (!seen.n) {
		fallback (c, first_ok, best);
		amb = true;
	} else {
		/* the layout order (s0, I, Fv, -A, K): no prior, no group count */
		Score bs = { 0 };
		int nbest = -1;
		DecList cur;
		for (k = 0; k < seen.n; k++) {
			const Score s = score_reading (c, &seen.a[k], first_ok, &cur);
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
			const Score s = score_reading (c, &seen.a[k], first_ok, &cur);
			amb = !score_cmp (&s, &bs) && !same_reading (best, &cur);
		}
		if (amb && ties) {
			/* the tied readings in K order, one per signature, for the K-tie cascade */
			int *order = malloc (seen.n * sizeof (int)), nt = 0, m;
			if (order) {
				for (k = 0; k < seen.n; k++) {
					const Score s = score_reading (c, &seen.a[k], first_ok, &cur);
					if (!score_cmp (&s, &bs)) {
						for (m = nt; m > 0 && asg_key_cmp (&seen.a[k], &seen.a[order[m - 1]]) < 0; m--) {
							order[m] = order[m - 1];
						}
						order[m] = k;
						nt++;
					}
				}
				for (k = 0; k < nt; k++) {
					score_reading (c, &seen.a[order[k]], first_ok, &cur);
					qsort (cur.d, cur.n, sizeof (Dec), dec_cmp_head);
					for (m = 0; m < ties->n && !same_reading (&ties->d[m], &cur); m++) {
						;
					}
					if (m == ties->n) {
						tielist_push (ties, &cur);
					}
				}
				free (order);
			}
		}
		qsort (best->d, best->n, sizeof (Dec), dec_cmp_head);
	}
	asglist_fini (&seen);
	for (i = 0; i <= NU; i++) {
		asglist_fini (&c->memo[i]);
	}
	if (apply_bzs5 (c, best, first_ok, ties, &amb)) {
		return amb;
	}
	post_rules (c, best, first_ok, ties, &amb);
	return amb;
}

/* ---------------------------------------------------------------------------------------------------- packet filling */

/* a decided instruction as the packet sees it (field values decoded) */
static void dec_to_insn(const Dec *d, UsipInsn *in) {
	int k;
	memset (in, 0, sizeof (*in));
	in->head = d->head;
	in->ntails = d->nt;
	for (k = 0; k < USIP_MAX_TAILS; k++) {
		in->tails[k] = d->t[k];
	}
	in->pseudo = d->pseudo;
	in->guard = d->guard;
	in->loopq = d->loopq;
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
}

/* the instructions of a reading into the packet (owner map, field values) */
static void fill_packet(UsipPacket *pk, const DecList *dec) {
	const int n = pk->nunits;
	int i, k;
	memset (pk->owner, 0xff, sizeof (pk->owner));
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		UsipInsn *in = &pk->insn[i];
		dec_to_insn (d, in);
		pk->owner[d->head] = i;
		for (k = 0; k < d->nt; k++) {
			pk->owner[d->t[k]] = i;
		}
	}
	pk->ninsn = dec->n;
	/* every unit must have an owner (the readings cover the packet); be defensive anyway */
	for (i = 0; i < n; i++) {
		if (pk->owner[i] == 0xff && pk->ninsn < NU) {
			UsipInsn *in = &pk->insn[pk->ninsn];
			memset (in, 0, sizeof (*in));
			in->head = i;
			in->pseudo = USIP_P_HWORD;
			in->kind = USIP_K_OTHER;
			in->mnem = ".hword";
			in->w = pk->units[i];
			pk->owner[i] = pk->ninsn++;
		}
	}
}

/* post-layout renames (apply_renames): an instruction whose units match a rename entry, whose reading
 * is one of the entry's rename_from (mnemonic or @kind) and whose constraints hold with the packet context takes the
 * entry's name, kind and operands; the score is untouched */
static int reg_token(const char *s, bool prev_word, int *len);
static void insn_text(const UsipPacket *pk, int i, RStrBuf *sb, bool mark);

static void apply_renames(UsipPacket *pk) {
	int i, j, k, cop_mask = 0;
	ut32 bf_dsts = 0;
	for (i = 0; i < pk->ninsn; i++) {
		const UsipInsn *in = &pk->insn[i];
		if (in->op && !strcmp (in->mnem, "cop") && (!strcmp (in->op->form, "cop") || !strcmp (in->op->form, "cop_FS0"))) {
			const int fi = field_index (in->op, "rA");
			if (fi >= 0 && fi < in->nvals) {
				cop_mask |= 1 << (in->vals[fi] & 15);
			}
		}
		if (waw_kind (in->kind) && (isalpha ((unsigned char)in->mnem[0]) || in->mnem[0] == '_') && strncmp (in->mnem, "st", 2)) {
			/* the nowaw guardian of the bit-field renames: the destination (first operand, a register followed by a comma)
			 * of every WAW-kind instruction of the packet (stores excluded), read from its text */
			RStrBuf sb;
			r_strbuf_init (&sb);
			insn_text (pk, i, &sb, false);
			const char *sp = strchr (r_strbuf_get (&sb), ' ');
			if (sp) {
				int len = 0;
				while (*sp == ' ') {
					sp++;
				}
				const int r = reg_token (sp, false, &len);
				if (r >= 0) {
					const char *q = sp + len;
					while (*q == ' ') {
						q++;
					}
					if (*q == ',') {
						bf_dsts |= 1U << r;
					}
				}
			}
			r_strbuf_fini (&sb);
		}
	}
	for (i = 0; i < pk->ninsn; i++) {
		UsipInsn *in = &pk->insn[i];
		const int nu = 1 + in->ntails;
		const char *kind = usip_kind_name (in->kind);
		CtxD ctxd = CTXD_INIT (pk->nunits, in->head, pk->units, in->head);
		ctxd.tail_dist = in->ntails == 1? in->tails[0] - in->head: -1;
		ctxd.tail_idx = in->ntails? in->tails[0]: -1;
		ctxd.cop_mask = cop_mask;
		ctxd.pk = pk;
		ctxd.bf_dsts = bf_dsts;
		ctxd.have_bf = true;
		ctxd.instr_index = i;
		for (j = 0; j < N_OPS; j++) {
			const UsipOpcode *f = &usip_opcodes[j];
			bool from = false;
			if (!(f->flags & USIP_F_RENAME) || (f->flags & (USIP_F_SPLIT | USIP_F_FUSE)) || f->nunits != nu || (in->w & f->mask) != f->value) {
				continue;
			}
			for (k = 0; k < f->nrename_from && !from; k++) {
				const char *r = f->rename_from[k];
				from = r[0] == '@'? !strcmp (r + 1, kind): !strcmp (r, in->mnem);
			}
			if (!from) {
				continue;
			}
			if (f->ncons && !cons_ok (f, in->w, in->head == 0, &ctxd, CM_FREE | CM_DEFER)) {
				continue;
			}
			in->op = f;
			in->kind = f->kind;
			in->mnem = f->name;
			in->pseudo = USIP_P_FORM;
			in->guard = USIP_G_NONE;
			in->has_target = false;
			in->target = 0;
			in->nvals = R_MIN (f->nfields, USIP_MAX_VALS);
			for (k = 0; k < in->nvals; k++) {
				in->vals[k] = field_value (f, k, in->w);
			}
			break;
		}
	}
}

static inline bool kind_delays(int kind) {
	switch (kind) {
	case USIP_K_BR: case USIP_K_BR16: case USIP_K_BR16D: case USIP_K_CALL: case USIP_K_CALL16:
	case USIP_K_CALLA: case USIP_K_JUMPA: case USIP_K_RET: case USIP_K_CALLR: case USIP_K_JR:
		return true;
	}
	return false;
}

/* post-layout fusion (the USIP_F_FUSE entries): two ADJACENT one-unit instructions whose readings are the entry's two
 * rename_from mnemonics (the head's by name, the tail's by shape) and whose units match the entry (+ its constraints: the same
 * rrr) become ONE two-unit instruction (movi rA, #2b || asr? rA, #b' = op72? rA, #2b, asr#b') */
static void fuse_pairs(UsipPacket *pk) {
	int i, j, k;
	for (i = 0; i + 1 < pk->ninsn; i++) {
		UsipInsn *in = &pk->insn[i];
		const UsipInsn *nx = &pk->insn[i + 1];
		if (in->ntails || nx->ntails || nx->head != in->head + 1) {
			continue;
		}
		const ut64 w = ((ut64)pk->units[in->head] << 16) | pk->units[nx->head];
		for (j = 0; j < N_OPS; j++) {
			const UsipOpcode *f = &usip_opcodes[j];
			if (!(f->flags & USIP_F_FUSE) || (f->flags & USIP_F_ADJ2) || f->nunits != 2 || (w & f->mask) != f->value || f->nrename_from < 1
				|| strcmp (in->mnem, f->rename_from[0])) {
				continue;
			}
			if (f->ncons && !cons_ok (f, w, in->head == 0, NULL, CM_FREE | CM_DEFER)) {
				continue;
			}
			in->op = f;
			in->kind = f->kind;
			in->mnem = f->name;
			in->pseudo = USIP_P_FORM;
			in->guard = USIP_G_NONE;
			in->has_target = false;
			in->target = 0;
			in->ntails = 1;
			in->tails[0] = nx->head;
			in->w = w;
			in->nvals = R_MIN (f->nfields, USIP_MAX_VALS);
			for (k = 0; k < in->nvals; k++) {
				in->vals[k] = field_value (f, k, w);
			}
			memmove (&pk->insn[i + 1], &pk->insn[i + 2], (pk->ninsn - i - 2) * sizeof (UsipInsn));
			pk->ninsn--;
			for (k = 0; k < pk->nunits; k++) {
				if (pk->owner[k] > i) {
					pk->owner[k]--;
				}
			}
			pk->owner[in->tails[0]] = i;
			break;
		}
	}
}

static bool pk_has_call(const UsipPacket *pk) {
	int i;
	for (i = 0; i < pk->ninsn; i++) {
		const int k = pk->insn[i].kind;
		if (k == USIP_K_CALL || k == USIP_K_CALL16 || k == USIP_K_CALLA || k == USIP_K_CALLR) {
			return true;
		}
	}
	return false;
}

/* R-slotc, ctx call_within_2_packets (slotc_mark): the slot pairs of the packet (stslot_slotc_h / _t) are
 * firm only with a call in their packet or in the two following ones; otherwise they take the stslot? twins.  The following packets
 * are the caller's first-pass readings (UsipGuardCtx.packet_at); when one of them cannot be seen the window ends there (a
 * whole-function scan clips the window at the function end), so the pair prints stslot?. */
static void slotc_mark(UsipPacket *pk, const UsipGuardCtx *g) {
	bool any = false;
	int i, k, q;
	for (i = 0; i < pk->ninsn && !any; i++) {
		const UsipInsn *in = &pk->insn[i];
		any = in->op && (usip_op_index (in->op) == USIP_FORM_STSLOT_SLOTC_H || usip_op_index (in->op) == USIP_FORM_STSLOT_SLOTC_T);
	}
	if (!any || pk_has_call (pk)) {
		return;
	}
	ut64 at = pk->addr + 2 * (ut64)pk->nunits;
	for (q = 0; q < 2; q++) {
		const UsipPacket *nx = (g && g->packet_at)? g->packet_at (g->user, at, false): NULL;
		if (!nx || !nx->nunits || nx->addr != at || nx->truncated) {
			break;
		}
		if (pk_has_call (nx)) {
			return;
		}
		at = nx->addr + 2 * (ut64)nx->nunits;
	}
	for (i = 0; i < pk->ninsn; i++) {
		UsipInsn *in = &pk->insn[i];
		const int idx = usip_op_index (in->op);
		if (idx != USIP_FORM_STSLOT_SLOTC_H && idx != USIP_FORM_STSLOT_SLOTC_T) {
			continue;
		}
		const UsipOpcode *f = &usip_opcodes[idx == USIP_FORM_STSLOT_SLOTC_H? USIP_FORM_STSLOT_SLOTC_H_Q: USIP_FORM_STSLOT_SLOTC_T_Q];
		in->op = f;
		in->kind = f->kind;
		in->mnem = f->name;
		in->nvals = R_MIN (f->nfields, USIP_MAX_VALS);
		for (k = 0; k < in->nvals; k++) {
			in->vals[k] = field_value (f, k, in->w);
		}
	}
}

static void finish_packet(UsipPacket *pk, const UsipGuardCtx *g) {
	apply_renames (pk);
	fuse_pairs (pk);
	slotc_mark (pk, g);
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
		case USIP_A_OFFB:
			/* signed offset with an explicit sign: [rA+0x4], [rA-0x6] */
			r_strbuf_appendf (&ob, v < 0? "-0x%"PFMT64x: "+0x%"PFMT64x, (ut64)(v < 0? -v: v));
			break;
		case USIP_A_FLAG:
		case USIP_A_LOOPN:
			r_strbuf_appendf (&ob, "%d", (int)v);
			break;
		default: {
			/* an immediate glued to a letter or to '=' is an index (the accumulator A{k}, the loop ?ss=N): decimal */
			const char *prev = r_strbuf_get (&ob);
			const size_t pl = strlen (prev);
			if (pl && (isalpha ((unsigned char)prev[pl - 1]) || prev[pl - 1] == '=')) {
				r_strbuf_appendf (&ob, "%d", (int)v);
			} else {
				append_imm (&ob, v);
			}
			break;
		}
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
	if (in->loopq && o + 1 < sizeof (tmp)) {
		/* loop #N?: the ? goes after the count */
		char *cm = strchr (tmp, ',');
		if (cm) {
			memmove (cm + 1, cm, strlen (cm) + 1);
			*cm = '?';
		}
	}
	if (*tmp) {
		r_strbuf_append (sb, " ");
		r_strbuf_append (sb, tmp);
	}
}

/* mnemonic and operands of an instruction at pc; mark = print the ? of an unverified target guard */
static void insn_text_at(const UsipInsn *in, ut64 pc, RStrBuf *sb, bool mark) {
	switch (in->pseudo) {
	case USIP_P_FORM:
		r_strbuf_append (sb, in->mnem);
		if (mark && in->guard == USIP_G_UNVERIFIED) {
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
		/* .word, or .dsp for the op C pair left by a failed compare-and-branch guard */
		r_strbuf_appendf (sb, "%s 0x%08x", in->mnem, (unsigned)(in->w & UT32_MAX));
		break;
	case USIP_P_W48:
		r_strbuf_appendf (sb, ".w48 0x%012"PFMT64x, (ut64)(in->w & 0xFFFFFFFFFFFFULL));
		break;
	case USIP_P_HI:
		r_strbuf_appendf (sb, ".hi 0x%04x", (unsigned)(in->w & 0xFFFF));
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

static void insn_text(const UsipPacket *pk, int i, RStrBuf *sb, bool mark) {
	insn_text_at (&pk->insn[i], usip_unit_addr (pk, i < pk->ninsn? pk->insn[i].head: 0), sb, mark);
}

/* the text of a decided instruction of a reading (no unverified mark) */
static void dec_text(const Dec *d, ut64 pc, RStrBuf *sb) {
	UsipInsn in;
	dec_to_insn (d, &in);
	insn_text_at (&in, pc, sb, false);
}

void usip_insn_text(const UsipPacket *pk, int i, RStrBuf *sb) {
	insn_text (pk, i, sb, true);
}

/* ---------------------------------------------------------------------------------------------------- K-tie cascade */

/* Register sets of the cascade as bit masks: bit r = rN (sp = r14, LR = r15), bit 16 + r = rN! (the high bank) */
#define RS_BIT(r, hi) (1U << ((r) + ((hi)? 16: 0)))
#define RS_ARGS   0x0000000FU                     /* r0-r3 */
#define RS_RET    0x00000003U                     /* r0, r1 */
#define RS_CALLER 0x00FF80FFU                     /* r0-r7, r0!-r7!, r15 */
#define RS_SKIP   0x0000C000U                     /* r14, r15: never scored */

enum { RF_NONE = 0, RF_UNK, RF_FRAME, RF_CALL, RF_STOP, RF_COND };

/* use of one instruction: dsts / srcs (regs_of, computed from the instruction text) */
typedef struct {
	ut32 dsts, srcs;
	ut8 flag;
	bool named;    /* the mnemonic is a real operation (no leading . nor trailing ?) */
	ut8 kind;
} RegUse;

/* summary of one packet of the du2 context (_pk_info) */
typedef struct {
	ut32 dsts, srcs;
	bool call, stop, cond, ret, join;
	ut64 a0;
	bool has_tgt;
	ut64 tgt_addr;
	int tgt;       /* index of the target packet of the last branch inside the context, -1 */
} PkInfo;

static inline bool is_wordc(char ch) {
	return isalnum ((unsigned char)ch) || ch == '_';
}

/* register token at s (not preceded by a word character): its bit, and its length in *len; -1 when none */
static int reg_token(const char *s, bool prev_word, int *len) {
	if (prev_word) {
		return -1;
	}
	if (s[0] == 'r' && isdigit ((unsigned char)s[1])) {
		int n = 0, j = 1;
		while (isdigit ((unsigned char)s[j])) {
			n = n * 10 + (s[j] - '0');
			j++;
		}
		const bool hi = s[j] == '!';
		if (hi) {
			j++;
		}
		if (is_wordc (s[j]) || n > 15) {
			return -1;
		}
		*len = j;
		return n + (hi? 16: 0);
	}
	if (!strncmp (s, "sp", 2) && !is_wordc (s[2])) {
		*len = 2;
		return 14;
	}
	if (!strncmp (s, "LR", 2) && !is_wordc (s[2])) {
		*len = 2;
		return 15;
	}
	return -1;
}

/* every register named in s, and the bases of the post-incremented accesses [rA]+ */
static void scan_regs(const char *s, ut32 *regs, ut32 *post) {
	const char *p;
	*regs = 0;
	if (post) {
		*post = 0;
	}
	for (p = s; *p; p++) {
		int len = 0;
		const int r = reg_token (p, p > s && is_wordc (p[-1]), &len);
		if (r < 0) {
			continue;
		}
		*regs |= 1U << r;
		if (post && p > s && p[-1] == '[' && p[len] == ']' && p[len + 1] == '+') {
			*post |= 1U << r;
		}
		p += len - 1;
	}
}

/* the operand is exactly a register, or a register pair rA:rB */
static bool gpr1(const char *s) {
	int len = 0;
	if (reg_token (s, false, &len) < 0) {
		return false;
	}
	if (!s[len]) {
		return true;
	}
	if (s[len] != ':' || s[len + 1] != 'r') {
		return false;
	}
	s += len + 1;
	return reg_token (s, false, &len) >= 0 && !s[len];
}

static bool in_list(const char *s, const char *const *list, size_t n) {
	size_t i;
	for (i = 0; i < n; i++) {
		if (!strcmp (s, list[i])) {
			return true;
		}
	}
	return false;
}

static bool br_kind(int kind) {
	return kind == USIP_K_BR || kind == USIP_K_BR16 || kind == USIP_K_BR16D || kind == USIP_K_LOOP || kind == USIP_K_JUMPA;
}

static bool call_kind(int kind) {
	return kind == USIP_K_CALL || kind == USIP_K_CALLA || kind == USIP_K_CALLR || kind == USIP_K_CALL16;
}

/* regs_of: the registers an instruction writes and reads, from its text */
static void regs_of(const UsipPacket *pk, int i, RegUse *out) {
	static const char *const rmw16[] = { "add", "sub", "or", "and", "xor", "rsub", "addi", "lsl", "lsr", "asr", "shl", "shr" };
	static const char *const rmw_any[] = { "cmov", "cmovi", "mac", "msu", "L_mac", "L_msu", "L_mac0", "L_msu0", "mac.9a?", "msu?" };
	static const char *const stop_mn[] = { "b", "b.s", "b.abs", "jr", "jr?", "ret", "ret.d", "ret.s", "ret?", "rti", "b.d" };
	static const char *const st_like[] = { "iow", "iow?", "mtcsr", "mtcsr?", "cop" };
	const UsipInsn *in = &pk->insn[i];
	const char *mt = in->mnem;
	char *ops[8];
	int nops = 0, k;
	ut32 regs = 0, post = 0;
	RStrBuf sb;
	memset (out, 0, sizeof (*out));
	out->kind = in->kind;
	out->named = mt[0] != '.' && mt[strlen (mt) - 1] != '?';
	if (in->kind == USIP_K_OTHER || in->kind == USIP_K_FMT) {
		out->flag = RF_UNK;
		return;
	}
	r_strbuf_init (&sb);
	insn_text (pk, i, &sb, false);
	char *body = r_strbuf_drain_nofree (&sb);
	r_strbuf_fini (&sb);
	if (!body) {
		return;
	}
	scan_regs (body, &regs, &post);
	/* the operands after the mnemonic, split at the commas */
	char *rest = strchr (body, ' ');
	if (rest) {
		*rest++ = 0;
		while (*rest && nops < (int)R_ARRAY_SIZE (ops)) {
			char *comma = strchr (rest, ',');
			if (comma) {
				*comma = 0;
			}
			r_str_trim (rest);
			ops[nops++] = rest;
			if (!comma) {
				break;
			}
			rest = comma + 1;
		}
	}
	if (in->kind == USIP_K_SAVE) {
		out->srcs = regs;
		out->flag = RF_FRAME;
	} else if (in->kind == USIP_K_RESTORE) {
		out->dsts = regs;
		out->flag = RF_FRAME;
	} else if (in->kind == USIP_K_RET || (br_kind (in->kind) && in_list (mt, stop_mn, R_ARRAY_SIZE (stop_mn))) || !strcmp (mt, "jr") || !strcmp (mt, "jr?")) {
		out->srcs = regs;
		out->flag = RF_STOP;
	} else if (br_kind (in->kind) || !strcmp (mt, "lpexit?") || !strcmp (mt, "lpexit")) {
		out->srcs = regs;
		out->flag = RF_COND;
	} else if (call_kind (in->kind)) {
		out->srcs = regs;
		out->flag = RF_CALL;
	} else if (in->kind == USIP_K_NOP) {
		/* nothing */
	} else if (in->kind == USIP_K_ST || !strncmp (mt, "st", 2) || in_list (mt, st_like, R_ARRAY_SIZE (st_like))) {
		out->dsts = post;
		out->srcs = regs;
	} else if (!nops) {
		out->dsts = post;
	} else if (!gpr1 (ops[0])) {
		/* accumulator / immediate / memory destination: every register is a source */
		out->dsts = post;
		out->srcs = regs;
	} else {
		ut32 d = 0, s = 0, r;
		scan_regs (ops[0], &d, NULL);
		out->dsts = d | post;
		for (k = 1; k < nops; k++) {
			scan_regs (ops[k], &r, NULL);
			s |= r;
		}
		const bool is16 = in_list (mt, rmw16, R_ARRAY_SIZE (rmw16));
		const bool rmw = in_list (mt, rmw_any, R_ARRAY_SIZE (rmw_any)) || (in->kind == USIP_K_ALU && is16 && nops == 2)
			|| (is16 && nops == 2 && !gpr1 (ops[1]));
		out->srcs = rmw? s | out->dsts: s;
	}
	free (body);
}

/* _pk_info over the instructions of a packet */
static void pk_info(const UsipPacket *pk, PkInfo *out) {
	int i;
	memset (out, 0, sizeof (*out));
	out->a0 = pk->addr;
	out->tgt = -1;
	for (i = 0; i < pk->ninsn; i++) {
		const UsipInsn *in = &pk->insn[i];
		RegUse u;
		regs_of (pk, i, &u);
		if (u.flag != RF_FRAME) {
			out->dsts |= u.dsts;
			out->srcs |= u.srcs;
			if (u.flag == RF_CALL) {
				out->call = true;
			} else if (u.flag == RF_STOP) {
				out->stop = true;
			} else if (u.flag == RF_COND) {
				out->cond = true;
			}
		}
		if (in->kind == USIP_K_RET) {
			out->ret = true;
		}
		if (in->has_target && (in->kind == USIP_K_BR || in->kind == USIP_K_BR16 || in->kind == USIP_K_BR16D)) {
			out->has_tgt = true;
			out->tgt_addr = in->target;
		}
	}
}

typedef struct {
	PkInfo pk[2 * DU2_W + 1];
	int n, p;   /* packets in the context, index of the packet being decoded */
} Du2Ctx;

typedef struct {
	int ev;        /* EV_* */
	double conf;
	int q;
} Event;

enum { EV_NONE = 0, EV_USE, EV_RETVAL, EV_DEAD, EV_ARG, EV_CLOB, EV_STOP, EV_DEF, EV_RET, EV_CLOBBERED, EV_LIVE, EV_UNDEF };

static inline bool has_reg(ut32 set, int r) {
	return (set >> r) & 1;
}

static Event ev(int e, double conf, int q) {
	Event x = { e, conf, q };
	return x;
}

static Event fwd_from(int r, int q0, const Du2Ctx *c, int W, double conf) {
	int q;
	for (q = q0; q < c->n && q < q0 + W; q++) {
		const PkInfo *pk = &c->pk[q];
		if (pk->join && q > q0) {
			conf *= 0.5;
		}
		if (has_reg (pk->srcs, r)) {
			return ev (EV_USE, conf, q);
		}
		if (pk->ret && (RS_RET & (1U << r))) {
			return ev (EV_RETVAL, conf, q);
		}
		if (has_reg (pk->dsts, r)) {
			return ev (EV_DEAD, conf, q);
		}
		if (pk->call) {
			if (RS_ARGS & (1U << r)) {
				return ev (EV_ARG, conf, q);
			}
			if (RS_CALLER & (1U << r)) {
				return ev (EV_CLOB, conf, q);
			}
		}
		if (pk->stop) {
			if (pk->tgt >= 0 && pk->tgt > q && W > 1) {
				return fwd_from (r, pk->tgt, c, W / 2, conf * 0.75);
			}
			return ev (EV_STOP, conf, q);
		}
		if (pk->cond) {
			conf *= 0.5;
		}
	}
	return ev (EV_NONE, conf, -1);
}

static inline bool ev_pos(int e) {
	return e == EV_USE || e == EV_ARG || e == EV_RETVAL;
}

static Event fwd_event(int r, int p, const Du2Ctx *c, int W) {
	const PkInfo *pk = &c->pk[p];
	Event res[2];
	int nres = 0, k;
	if (pk->stop) {
		if (pk->tgt >= 0) {
			return fwd_from (r, pk->tgt, c, W, 1.0);
		}
		return ev (EV_STOP, 1.0, -1);
	}
	if (p + 1 < c->n) {
		res[nres++] = fwd_from (r, p + 1, c, W, 1.0);
	}
	if (pk->cond && pk->tgt >= 0 && pk->tgt != p + 1 && pk->tgt < c->n) {
		res[nres++] = fwd_from (r, pk->tgt, c, W, 1.0);
	}
	if (!nres) {
		return ev (EV_NONE, 1.0, -1);
	}
	if (nres == 1) {
		return res[0];
	}
	int best = -1;
	bool other_dead = false, all_dead = true, any_dead = false, any_clob = false;
	double minconf = res[0].conf;
	for (k = 0; k < nres; k++) {
		if (ev_pos (res[k].ev) && (best < 0 || res[k].conf > res[best].conf)) {
			best = k;
		}
		other_dead |= res[k].ev == EV_DEAD;
		all_dead &= res[k].ev == EV_DEAD;
		any_dead |= res[k].ev == EV_DEAD;
		any_clob |= res[k].ev == EV_CLOB;
		minconf = R_MIN (minconf, res[k].conf);
	}
	if (best >= 0) {
		return ev (res[best].ev, res[best].conf * (other_dead? 0.75: 1.0), res[best].q);
	}
	if (all_dead) {
		return ev (EV_DEAD, minconf, res[0].q);
	}
	if (any_dead) {
		return ev (EV_DEAD, 0.5 * minconf, res[0].q);
	}
	if (any_clob) {
		return ev (EV_CLOB, 0.5, res[0].q);
	}
	return ev (EV_NONE, 1.0, -1);
}

/* the last definition of r before packet p (window W); the context never reaches a function start (the caller does
 * not know them), so an exhausted window is `none` rather than the arg/undef event of a whole-function scan */
static Event bwd_def(int r, int p, const Du2Ctx *c, int W) {
	double conf = 1.0;
	int q = p - 1;
	const int lo = R_MAX (-1, p - 1 - W);
	while (q > lo) {
		const PkInfo *pk = &c->pk[q];
		if (c->pk[q + 1].join) {
			conf *= 0.5;
		}
		if (pk->stop) {
			return ev (EV_STOP, conf, q);
		}
		if (pk->call) {
			if (RS_RET & (1U << r)) {
				return ev (EV_RET, conf, q);
			}
			if (RS_CALLER & (1U << r)) {
				return ev (EV_CLOBBERED, conf, q);
			}
		}
		if (has_reg (pk->dsts, r)) {
			return ev (EV_DEF, conf, q);
		}
		if (has_reg (pk->srcs, r)) {
			return ev (EV_LIVE, conf, q);
		}
		q--;
	}
	return ev (EV_NONE, conf, -1);
}

static bool read_between(int r, int q0, int q1, const Du2Ctx *c) {
	int q;
	for (q = q0 + 1; q < q1; q++) {
		if (q >= 0 && q < c->n && has_reg (c->pk[q].srcs, r)) {
			return true;
		}
	}
	return false;
}

/* a candidate reading of the cascade */
typedef struct {
	UsipPacket pk;
	RegUse use[NU];
	char *text[NU];      /* instruction texts, sorted */
	ut32 D, S;           /* registers written / read (SKIP and frame excluded) */
	double score;
	bool alive;
} Cand;

static int cmp_str(const void *a, const void *b) {
	return strcmp (*(const char *const *)a, *(const char *const *)b);
}

/* the register names in the order the cascade iterates them (sorted as strings: r0, r0!, r1, r1!, r10, ...) */
static int reg_order[32];

static int cmp_regname(const void *a, const void *b) {
	char na[8], nb[8];
	const int x = *(const int *)a, y = *(const int *)b;
	snprintf (na, sizeof (na), "r%d%s", x & 15, x >= 16? "!": "");
	snprintf (nb, sizeof (nb), "r%d%s", y & 15, y >= 16? "!": "");
	return strcmp (na, nb);
}

static void reg_order_init(void) {
	int i;
	if (reg_order[1]) {
		return;
	}
	for (i = 0; i < 32; i++) {
		reg_order[i] = i;
	}
	qsort (reg_order, 32, sizeof (int), cmp_regname);
}

/* number of registers written by two instructions of the reading (WAW kinds only) */
static int waw_of(const Cand *cd) {
	ut32 once = 0, twice = 0;
	int i, n = 0;
	for (i = 0; i < cd->pk.ninsn; i++) {
		const RegUse *u = &cd->use[i];
		if (!waw_kind (u->kind)) {
			continue;
		}
		twice |= once & u->dsts;
		once |= u->dsts;
	}
	for (i = 0; i < 32; i++) {
		n += (twice >> i) & 1;
	}
	return n;
}

/* du2_scores: the differential use-definition score of every live candidate */
static void du2_scores(Cand *cands, int ncands, const int *alive, int nalive, int p, const Du2Ctx *c, int W) {
	ut32 unionD = 0, interD = 0xFFFFFFFFU, unionS = 0, interS = 0xFFFFFFFFU;
	int a, i, k;
	for (a = 0; a < nalive; a++) {
		const Cand *cd = &cands[alive[a]];
		unionD |= cd->D;
		interD &= cd->D;
		unionS |= cd->S;
		interS &= cd->S;
	}
	const ut32 diffD = unionD & ~interD, diffS = unionS & ~interS;
	for (a = 0; a < nalive; a++) {
		Cand *cd = &cands[alive[a]];
		double sc = 0.0;
		for (i = 0; i < 32; i++) {
			const int r = reg_order[i];
			if (!has_reg (cd->D & diffD, r)) {
				continue;
			}
			Event e;
			if (c->pk[p].call && (RS_CALLER & (1U << r))) {
				e = ev ((RS_ARGS & (1U << r))? EV_ARG: EV_CLOB, 1.0, p);
			} else {
				e = fwd_event (r, p, c, W);
			}
			const Event b = bwd_def (r, p, c, W);
			const bool live_in = b.ev == EV_DEF || b.ev == EV_RET || b.ev == EV_LIVE || b.ev == EV_ARG;
			double v = 0.0;
			switch (e.ev) {
			case EV_USE: case EV_RETVAL: v = 1.0 + (live_in? 0.0: 1.0); break;
			case EV_ARG: v = 1.0; break;
			case EV_DEAD: v = -1.5; break;
			case EV_CLOB: v = -0.75; break;
			default: break;
			}
			sc += v * e.conf;
		}
		for (i = 0; i < 32; i++) {
			const int r = reg_order[i];
			if (!has_reg (cd->S & diffS, r)) {
				continue;
			}
			const Event b = bwd_def (r, p, c, W);
			double v = 0.0;
			if (b.ev == EV_DEF) {
				bool readers_named = true;
				for (k = 0; k < cd->pk.ninsn; k++) {
					const RegUse *u = &cd->use[k];
					if (has_reg (u->srcs, r) && u->flag != RF_FRAME && !u->named) {
						readers_named = false;
					}
				}
				const bool sole = readers_named && !read_between (r, b.q, p, c) && !ev_pos (fwd_event (r, p, c, W).ev);
				v = 1.0 + (sole? 1.0: 0.0);
			} else {
				switch (b.ev) {
				case EV_RET: v = 1.0; break;
				case EV_CLOBBERED: v = -1.5; break;
				case EV_LIVE: case EV_ARG: v = 0.5; break;
				case EV_UNDEF: v = -1.0; break;
				default: break;
				}
			}
			sc += v * b.conf;
		}
		cd->score = sc;
	}
}

static void cand_fini(Cand *cd) {
	int i;
	for (i = 0; i < NU; i++) {
		free (cd->text[i]);
		cd->text[i] = NULL;
	}
}

/* decide_ties for one packet: pk = the renamed K reading (the context entry of the packet itself),
 * ties = the tied readings (raw, K order).  Returns the chosen tie index (-1: the tie stays with K) and *how. */
static int cascade(const UsipPacket *pk, const TieList *ties, const UsipGuardCtx *g, ut8 *how) {
	const int n = ties->n;
	Cand *cands = calloc (n, sizeof (Cand));
	int alive[64], nalive = 0, chosen = -1, i, k, a;
	*how = USIP_T_NONE;
	if (!cands || n < 2 || n > (int)R_ARRAY_SIZE (alive)) {
		free (cands);
		return -1;
	}
	reg_order_init ();
	for (i = 0; i < n; i++) {
		Cand *cd = &cands[i];
		cd->pk.addr = pk->addr;
		cd->pk.nunits = pk->nunits;
		memcpy (cd->pk.units, pk->units, sizeof (pk->units));
		fill_packet (&cd->pk, &ties->d[i]);
		for (k = 0; k < cd->pk.ninsn; k++) {
			RStrBuf sb;
			regs_of (&cd->pk, k, &cd->use[k]);
			r_strbuf_init (&sb);
			insn_text (&cd->pk, k, &sb, false);
			cd->text[k] = r_strbuf_drain_nofree (&sb);
			r_strbuf_fini (&sb);
			if (cd->use[k].flag != RF_FRAME) {
				cd->D |= cd->use[k].dsts & ~RS_SKIP;
				cd->S |= cd->use[k].srcs & ~RS_SKIP;
			}
		}
		qsort (cd->text, cd->pk.ninsn, sizeof (char *), cmp_str);
		cd->alive = true;
		alive[nalive++] = i;
	}
	/* dedup: identical multisets of instruction texts -> the K reading */
	bool same = true;
	for (i = 1; i < n && same; i++) {
		same = cands[i].pk.ninsn == cands[0].pk.ninsn;
		for (k = 0; same && k < cands[0].pk.ninsn; k++) {
			same = cands[i].text[k] && cands[0].text[k] && !strcmp (cands[i].text[k], cands[0].text[k]);
		}
	}
	if (same) {
		chosen = 0;
		*how = USIP_T_DEDUP;
	}
	/* nowaw: the readings without a double register write */
	if (chosen < 0) {
		int ok[64], nok = 0;
		for (a = 0; a < nalive; a++) {
			if (waw_of (&cands[alive[a]]) == 0) {
				ok[nok++] = alive[a];
			}
		}
		if (nok && nok < nalive) {
			memcpy (alive, ok, nok * sizeof (int));
			nalive = nok;
			if (nalive == 1) {
				chosen = alive[0];
				*how = USIP_T_NOWAW;
			}
		}
	}
	/* du2: the differential use-definition score over the neighbouring packets */
	if (chosen < 0 && nalive > 1) {
		bool all_waw = true;
		for (a = 0; a < nalive && all_waw; a++) {
			all_waw = waw_of (&cands[alive[a]]) > 0;
		}
		if (!all_waw) {
			Du2Ctx *c = calloc (1, sizeof (Du2Ctx));
			if (c) {
				const UsipPacket *back[DU2_W];
				int nb = 0, j;
				ut64 at = pk->addr;
				for (nb = 0; nb < DU2_W && g && g->packet_at; nb++) {
					const UsipPacket *b = g->packet_at (g->user, at, true);
					if (!b || !b->nunits || b->addr + 2 * (ut64)b->nunits != at) {
						break;
					}
					back[nb] = b;
					at = b->addr;
				}
				for (j = nb - 1; j >= 0; j--) {
					pk_info (back[j], &c->pk[c->n++]);
				}
				c->p = c->n;
				pk_info (pk, &c->pk[c->n++]);
				at = pk->addr + 2 * (ut64)pk->nunits;
				for (j = 0; j < DU2_W && g && g->packet_at; j++) {
					const UsipPacket *f = g->packet_at (g->user, at, false);
					if (!f || !f->nunits || f->addr != at) {
						break;
					}
					pk_info (f, &c->pk[c->n++]);
					at = f->addr + 2 * (ut64)f->nunits;
				}
				for (j = 0; j < c->n; j++) {
					PkInfo *x = &c->pk[j];
					if (g && g->branch_target && g->branch_target (g->user, x->a0) == 1) {
						x->join = true;
					}
					for (k = 0; k < c->n; k++) {
						if (c->pk[k].has_tgt && c->pk[k].tgt_addr == x->a0) {
							x->join = true;
						}
						if (x->has_tgt && x->tgt_addr == c->pk[k].a0) {
							x->tgt = k;
						}
					}
				}
				du2_scores (cands, n, alive, nalive, c->p, c, DU2_W);
				/* the best score wins by a margin of 1 (ties: the first) */
				int b0 = -1, b1 = -1;
				for (a = 0; a < nalive; a++) {
					const double s = cands[alive[a]].score;
					if (b0 < 0 || s > cands[alive[b0]].score) {
						b1 = b0;
						b0 = a;
					} else if (b1 < 0 || s > cands[alive[b1]].score) {
						b1 = a;
					}
				}
				if (b0 >= 0 && b1 >= 0 && cands[alive[b0]].score - cands[alive[b1]].score >= 1.0) {
					chosen = alive[b0];
					*how = USIP_T_DU2;
				}
				free (c);
			}
		}
	}
	for (i = 0; i < n; i++) {
		cand_fini (&cands[i]);
	}
	free (cands);
	return chosen;
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

void usip_decode_packet(UsipPacket *pk, ut64 addr, const ut16 *units, int n, bool truncated, const UsipGuardCtx *g) {
	ut64 addrs[NU];
	DecList dec;
	TieList ties = { 0 };
	int i;
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
	const bool cascade_on = !(g && (g->flags & USIP_GUARD_NO_CASCADE));
	pk->ambiguous = parse_packet (g, units, addrs, n, true, addr, &dec, cascade_on? &ties: NULL);
	fill_packet (pk, &dec);
	finish_packet (pk, g);
	if (pk->ambiguous && ties.n >= 2) {
		/* the K-tie cascade: dedup / nowaw / du2 over the tied readings; the chosen one replaces the K reading */
		ut8 how = USIP_T_NONE;
		const int chosen = cascade (pk, &ties, g, &how);
		if (chosen >= 0) {
			Ctx c = { 0 };
			DecList d2 = ties.d[chosen];
			c.units = pk->units;
			c.n = n;
			c.pk0 = addr;
			c.guard = g;
			memcpy (c.addrs, addrs, n * sizeof (ut64));
			bool amb2 = false;
			if (!apply_bzs5 (&c, &d2, ties.first_ok, NULL, &amb2)) {
				post_rules (&c, &d2, ties.first_ok, NULL, &amb2);
			}
			fill_packet (pk, &d2);
			finish_packet (pk, g);
			pk->ambiguous = false;
			pk->tiebreak = how;
		}
	}
	tielist_fini (&ties);
}
