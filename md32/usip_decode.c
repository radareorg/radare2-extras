/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* uSIP packet decoder: a table-driven reading of VLIW packets (parse_group, group_parses, score, parse_packet)
 * over the generated form table usip_opcodes.h.  The reading
 * chosen for a packet is deterministic: among the consistent readings the one with the fewest unknown units, then
 * the fewest instructions, then the fewest groups, then the smallest tie-break penalty; equal scores keep the first
 * enumerated reading.  No external knowledge is used. */

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
	static const char *const names[] = {
		"alu", "alu32", "bit", "br", "br16", "br16d", "call", "call16", "calla", "callr", "csr", "dsp", "dspacc",
		"fmt", "jumpa", "ld", "loop", "mem16", "mov", "mov32", "movi", "movi21", "movi32", "mul", "nop", "other",
		"restore", "ret", "save", "st", "sys"
	};
	return (kind >= 0 && kind < (int)R_ARRAY_SIZE (names))? names[kind]: "?";
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
	case USIP_A_SIMM:
	case USIP_A_DISP:
		return sext (raw, nb) * sc;
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
		return (st64)(raw * (ut64)sc);
	}
}

static inline bool is_hi1010(ut32 u) {
	return (u >> 15) == 0 && ((u >> 9) & 0xF) == 0xA;
}

static inline bool is_osyl(ut16 u) {
	return ((u >> 11) & 7) == 7;
}

/* ---------------------------------------------------------------------------------------------------- matching */

static const UsipOpcode *match16(ut16 u, bool first);

/* is the unit a named 16-bit op (in tail position if tail)?  Format-only shapes count, loose syllables do not. */
static bool known16(ut16 u, bool tail) {
	const UsipOpcode *f = match16 (u | 0x8000, !tail);
	return f && f->kind != USIP_K_OTHER && !(f->flags & USIP_F_UNKNOWN16);
}

static bool cons_ok(const UsipOpcode *op, ut64 w, bool first, int pktlen) {
	int i, j;
	for (i = 0; i < op->ncons; i++) {
		const UsipCons *c = &op->cons[i];
		const st64 v = c->field != USIP_NOFIELD? field_value (op, c->field, w): 0;
		const ut16 t = w & 0xFFFF;
		bool ok = true;
		switch (c->op) {
		case USIP_C_EQ: ok = v == c->vals[0]; break;
		case USIP_C_NE: ok = v != c->vals[0]; break;
		case USIP_C_LT: ok = v < c->vals[0]; break;
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
		case USIP_C_RANGE: ok = v >= c->vals[0] && v < c->vals[1]; break;
		case USIP_C_RANGES:
			ok = false;
			for (j = 0; j + 1 < c->nvals; j += 2) {
				ok |= v >= c->vals[j] && v < c->vals[j + 1];
			}
			break;
		case USIP_C_EVEN: ok = (v & 1) == 0; break;
		case USIP_C_NOT_HI1010: ok = !is_hi1010 ((ut32)v); break;
		case USIP_C_EQ_FIELDS: ok = v == field_value (op, c->field2, w); break;
		case USIP_C_PACKET_LEN: ok = pktlen == c->vals[0]; break;
		case USIP_C_SLOT0_EXCLUDES_HEAD: {
			const ut16 h = (w >> (op->width - 16)) & 0xFFFF;
			ok = !(first && (h & (ut16)c->vals[0]) == (ut16)c->vals[1]);
			break;
		}
		case USIP_C_ANY_EQ: ok = v == c->vals[0] || field_value (op, c->field2, w) == c->vals[0]; break;
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

/* first matching 16-bit form (context-only forms excluded); cached per (unit, slot) */
static ut16 k16cache[2][0x10000];   /* 0 = unknown, 0xffff = none, else index + 1 */

static const UsipOpcode *match16(ut16 u, bool first) {
	ut16 *slot = &k16cache[first? 1: 0][u];
	if (*slot) {
		return *slot == 0xffff? NULL: &usip_opcodes[*slot - 1];
	}
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 1 || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)
			|| ((f->flags & USIP_F_NOTSLOT0) && first) || (u & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, u, first, -1)) {
			continue;
		}
		*slot = i + 1;
		return f;
	}
	*slot = 0xffff;
	return NULL;
}

static const UsipOpcode *match32(ut16 h, ut16 t, bool first) {
	const ut64 w = ((ut64)h << 16) | t;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 2 || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)
			|| ((f->flags & USIP_F_NOTSLOT0) && first) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, -1)) {
			continue;
		}
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
		if (f->nunits != 3 || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)) {
			continue;
		}
		if ((w & (f->mask & 0xFFFFFFFF0000ULL)) == (f->value & 0xFFFFFFFF0000ULL)) {
			return true;
		}
	}
	return false;
}

static const UsipOpcode *match48(ut16 h, ut16 hi, ut16 lo, bool first) {
	const ut64 w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != 3 || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first) || (w & f->mask) != f->value) {
			continue;
		}
		if (f->ncons && !cons_ok (f, w, first, -1)) {
			continue;
		}
		return f;
	}
	return NULL;
}

/* ret / save / restore never take tails */
static inline bool never_tail(ut16 h) {
	return (h & 0x3FFF) == 0x1EF9 || (h & 0x3F0F) == 0x1F05;
}

static bool head_has_cands(ut16 h, int nunits, bool first) {
	int i;
	for (i = 0; i < N_OPS; i++) {
		const UsipOpcode *f = &usip_opcodes[i];
		if (f->nunits != nunits || (f->flags & USIP_F_CTX) || ((f->flags & USIP_F_SLOT0) && !first)) {
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

/* consistent readings of one group of n units (heads first, tails round-robin); only the ones with the fewest bare
 * heads without a named 16-bit reading are kept (parse_group) */
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
		/* itertools.product over the sorted allowed sets: the last head varies fastest */
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
						if (Ts[i] == 1) {
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
	int n;
	AsgList memo[NU + 1];
	bool memo_done[NU + 1];
} Ctx;

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
		if (j < n && (units[j] >> 15)) {
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
	ut8 t[2];
	ut8 pseudo;
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

static void set_target(Dec *d, ut64 pc) {
	const UsipOpcode *f = d->op;
	int i;
	d->has_target = false;
	if (!f) {
		return;
	}
	for (i = 0; i < f->nfields; i++) {
		const int t = f->fields[i].type;
		if (t == USIP_A_DISP || t == USIP_A_UDISP) {
			d->target = (pc + (ut64)field_value (f, i, d->w)) & UT32_MAX;
			d->has_target = true;
			return;
		}
		if (t == USIP_A_ABSADDR && !strcmp (f->fields[i].name, "target")) {
			d->target = (ut64)field_value (f, i, d->w);
			d->has_target = true;
			return;
		}
	}
}

static Dec dec16(ut64 pc, ut16 u, bool first) {
	Dec d = { 0 };
	d.nt = 0;
	d.w = u;
	d.op = match16 (u, first);
	if (!d.op) {
		d.pseudo = USIP_P_HWORD;
		d.kind = USIP_K_OTHER;
		d.mnem = ".hword";
		return d;
	}
	d.kind = d.op->kind;
	d.mnem = d.op->name;
	if ((d.op->flags & USIP_F_XBYTE) && ((u >> 8) & 1)) {
		d.mnem = d.op->name[0] == 'l'? "ld.b": "st.b";
	}
	set_target (&d, pc);
	return d;
}

static Dec dec32(ut64 pc, ut16 h, ut16 t, bool first) {
	Dec d = { 0 };
	d.nt = 1;
	d.w = ((ut64)h << 16) | t;
	d.op = match32 (h, t, first);
	if (!d.op) {
		d.pseudo = USIP_P_WORD;
		d.kind = USIP_K_OTHER;
		d.mnem = ".word";
		return d;
	}
	d.kind = d.op->kind;
	d.mnem = d.op->name;
	set_target (&d, pc);
	return d;
}

static Dec dec48(ut64 pc, ut16 h, ut16 hi, ut16 lo, bool first) {
	Dec d = { 0 };
	d.nt = 2;
	d.w = ((ut64)h << 32) | ((ut64)hi << 16) | lo;
	d.op = match48 (h, hi, lo, first);
	if (!d.op) {
		d.pseudo = USIP_P_W48;
		d.kind = USIP_K_OTHER;
		d.mnem = ".w48";
		return d;
	}
	d.kind = d.op->kind;
	d.mnem = d.op->name;
	set_target (&d, pc);
	return d;
}

static inline bool is_named(const Dec *d) {
	return d->kind != USIP_K_OTHER && d->kind != USIP_K_FMT;
}

static inline bool is_ctrl_kind(int kind) {
	return kind == USIP_K_BR || kind == USIP_K_CALL || kind == USIP_K_LOOP;
}

/* decode one assignment into instructions, applying the adjacency rules and the context rules (decode_asg) */
static void decode_asg(const Ctx *c, const Asg *asg, bool first_ok, DecList *out) {
	const ut16 *units = c->units;
	int m;
	out->n = 0;
	for (m = 0; m < asg->n; m++) {
		const int i = asg->head[m];
		const ut16 h = units[i];
		const ut64 pc = c->addrs[i];
		const bool first = i == 0 && first_ok;
		Dec d;
		Dec *prev = out->n? &out->d[out->n - 1]: NULL;
		if (asg->nt[m] == 0) {
			d = dec16 (pc, h, first);
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
						nd.op = f;
						nd.kind = f->kind;
						nd.mnem = f->name;
						nd.w = ((ut64)prev_raw << 16) | h;
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
			d = dec32 (pc, h, t, first);
			if (d.op && (d.op->flags & USIP_F_ADJ1) && dist > 1) {
				/* adjacency violated: two 16-bit units instead */
				Dec a = dec16 (pc, h, first);
				Dec b = dec16 (c->addrs[ti], t, false);
				a.head = i;
				b.head = ti;
				out->d[out->n++] = a;
				out->d[out->n++] = b;
				continue;
			}
			if (d.op && (d.op->flags & USIP_F_ADJCTRL) && is_ctrl_kind (d.op->kind) && (dist > 2 || (S == 1 && dist > 1))) {
				d.pseudo = USIP_P_WORD_CTRL;
				d.op = NULL;
				d.kind = USIP_K_OTHER;
				d.mnem = ".word";
				d.has_target = false;
			}
			d.t[0] = ti;
		} else {
			d = dec48 (pc, h, units[asg->t[m][0]], units[asg->t[m][1]], first);
			d.t[0] = asg->t[m][0];
			d.t[1] = asg->t[m][1];
		}
		d.head = i;
		out->d[out->n++] = d;
	}
}

static bool mn_in_fam48(const char *mn) {
	static const char *const fam[] = { "lea", "add", "ld.w", "ld.h", "ld.hu", "ld.b?", "ld.bu", "st.w", "st.h", "st.b" };
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

typedef struct {
	int score;    /* quarter units: unknown units + tie-break penalties */
	int ninsn;
	int ngroups;
} Score;

static int score_cmp(const Score *a, const Score *b) {
	if (a->score != b->score) {
		return a->score < b->score? -1: 1;
	}
	if (a->ninsn != b->ninsn) {
		return a->ninsn < b->ninsn? -1: 1;
	}
	if (a->ngroups != b->ngroups) {
		return a->ngroups < b->ngroups? -1: 1;
	}
	return 0;
}

/* score: unknown units, then the documented tie-break penalties */
static Score score_reading(const Ctx *c, const Asg *asg, int ngroups, bool first_ok, DecList *dec) {
	const ut16 *units = c->units;
	Score s = { 0 };
	int unnamed = 0, pen = 0, i, j;
	ut8 tails_of7 = 0;
	decode_asg (c, asg, first_ok, dec);
	for (i = 0; i < dec->n; i++) {
		const Dec *d = &dec->d[i];
		if ((units[d->head] & 0xF) == 7 && d->nt) {
			tails_of7 |= 1 << d->t[0];
		}
		if (d->kind == USIP_K_OTHER) {
			unnamed += 1 + d->nt;
		} else if (d->kind == USIP_K_FMT) {
			unnamed += 1;
			if (!strcmp (d->mnem, ".hi") || !strcmp (d->mnem, ".hilo")) {
				pen += Q (0.25);
			}
		} else if (d->nt == 2 && mn_in_fam48 (d->mnem) && is_hi1010 (units[d->t[0]]) && (((units[d->head] >> 4) & 0xF) == 14 || ((units[d->head] >> 4) & 0xF) == 15)) {
			pen += Q (0.5);
		} else if ((d->kind == USIP_K_LD || d->kind == USIP_K_ST) && d->nt == 1
			&& !((units[d->head] & 0xF) == 4 && ((units[d->t[0]] >> 12) & 3) == 2)) {
			const int off = units[d->t[0]] & 0xFFF;
			if ((ends_with (d->mnem, ".w") && (off & 3)) || (ends_with (d->mnem, ".h") && (off & 1))) {
				pen += Q (0.5);
			}
		}
		if (!d->nt && units[d->head] == 0x4000) {
			pen += Q (0.5);
		}
		for (j = 0; j < d->nt; j++) {
			const ut16 u = units[d->t[j]];
			if ((u >> 14) == 0 && (u & 7) == 7 && ((u >> 8) & 1) == 0) {
				pen += Q (0.5);
			}
		}
	}
	for (j = 0; j < c->n; j++) {
		if (is_osyl (units[j]) && !(tails_of7 & (1 << j))) {
			pen += Q (0.75);
		}
	}
	s.score = Q (unnamed) + pen;
	s.ninsn = dec->n;
	s.ngroups = ngroups;
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
			Dec d = dec16 (c->addrs[i], h, first);
			d.head = i;
			out->d[out->n++] = d;
			i++;
			continue;
		}
		Dec d = dec32 (c->addrs[i], h, units[i + 1], first);
		if (!is_named (&d)) {
			Dec d16 = dec16 (c->addrs[i], h, first);
			if (is_named (&d16)) {
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

static bool parse_packet(const ut16 *units, const ut64 *addrs, int n, bool first_ok, DecList *best);

/* the whole packet: enumerate the readings, score them, apply the packet-level context rules (parse_packet) */
static bool parse_packet(const ut16 *units, const ut64 *addrs, int n, bool first_ok, DecList *best) {
	int i, k;
	best->n = 0;
	if (n == 1) {
		Dec d = dec16 (addrs[0], units[0], first_ok);
		d.head = 0;
		best->d[best->n++] = d;
		return false;
	}
	Ctx c = { 0 };
	c.units = units;
	c.n = n;
	memcpy (c.addrs, addrs, n * sizeof (ut64));
	if (first_ok) {
		int hi, lo;
		if (abs_prefix (&c, &hi, &lo)) {
			Dec d0 = dec48 (addrs[0], units[0], units[hi], units[lo], true);
			d0.head = 0;
			d0.t[0] = hi;
			d0.t[1] = lo;
			best->d[best->n++] = d0;
			ut16 ru[NU];
			ut64 ra[NU];
			int ri[NU], nr = 0;
			for (k = 1; k < n; k++) {
				if (k != hi && k != lo) {
					ru[nr] = units[k];
					ra[nr] = addrs[k];
					ri[nr] = k;
					nr++;
				}
			}
			bool amb = false;
			if (nr > 1) {
				DecList sub;
				amb = parse_packet (ru, ra, nr, false, &sub);
				for (i = 0; i < sub.n; i++) {
					Dec d = sub.d[i];
					d.head = ri[d.head];
					for (k = 0; k < d.nt; k++) {
						d.t[k] = ri[d.t[k]];
					}
					best->d[best->n++] = d;
				}
			} else if (nr == 1) {
				Dec d = dec16 (ra[0], ru[0], false);
				d.head = ri[0];
				best->d[best->n++] = d;
			}
			return amb;
		}
	}
	const AsgList *all = group_parses (&c, 0, first_ok);
	/* dedup by assignment, keeping the smallest group count and the first-seen order */
	AsgList seen = { 0 };
	for (i = 0; i < all->n; i++) {
		const Asg *a = &all->a[i];
		for (k = 0; k < seen.n; k++) {
			if (!memcmp (&seen.a[k], a, sizeof (Asg))) {
				break;
			}
		}
		if (k < seen.n) {
			if (all->aux[i] < seen.aux[k]) {
				seen.aux[k] = all->aux[i];
			}
		} else {
			asglist_push (&seen, a, all->aux[i]);
		}
	}
	bool amb;
	if (!seen.n) {
		fallback (&c, first_ok, best);
		amb = true;
	} else {
		Score bs = { 0 };
		int nbest = -1;
		DecList cur;
		amb = false;
		for (k = 0; k < seen.n; k++) {
			const Score s = score_reading (&c, &seen.a[k], seen.aux[k], first_ok, &cur);
			if (nbest < 0 || score_cmp (&s, &bs) < 0) {
				bs = s;
				nbest = k;
				*best = cur;
			}
		}
		for (k = 0; k < seen.n && !amb; k++) {
			if (k == nbest) {
				continue;
			}
			const Score s = score_reading (&c, &seen.a[k], seen.aux[k], first_ok, &cur);
			amb = s.score == bs.score && s.ninsn == bs.ninsn;
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
		if ((units[0] & f->mask) == f->value && cons_ok (f, units[0], true, 2)) {
			Dec d0 = { 0 };
			d0.head = 0;
			d0.op = f;
			d0.kind = f->kind;
			d0.mnem = f->name;
			d0.w = units[0];
			set_target (&d0, addrs[0]);
			Dec d1 = dec16 (addrs[1], units[1], false);
			d1.head = 1;
			best->n = 0;
			best->d[best->n++] = d0;
			best->d[best->n++] = d1;
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
	case USIP_K_CALLA: case USIP_K_JUMPA: case USIP_K_RET: case USIP_K_CALLR:
		return true;
	}
	return false;
}

void usip_decode_packet(UsipPacket *pk, ut64 addr, const ut16 *units, int n, bool truncated) {
	ut64 addrs[NU];
	DecList dec;
	int i, k;
	memset (pk, 0, sizeof (*pk));
	n = R_MIN (R_MAX (n, 1), NU);
	pk->addr = addr;
	pk->nunits = n;
	pk->truncated = truncated;
	memcpy (pk->units, units, n * sizeof (ut16));
	for (i = 0; i < n; i++) {
		addrs[i] = addr + 2 * (ut64)i;
	}
	pk->ambiguous = parse_packet (units, addrs, n, true, &dec);
	memset (pk->owner, 0xff, sizeof (pk->owner));
	for (i = 0; i < dec.n; i++) {
		const Dec *d = &dec.d[i];
		UsipInsn *in = &pk->insn[i];
		in->head = d->head;
		in->ntails = d->nt;
		in->tails[0] = d->t[0];
		in->tails[1] = d->t[1];
		in->pseudo = d->pseudo;
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
		case USIP_A_FLAG:
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
