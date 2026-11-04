/* radare - LGPL - Copyright 2026 - pancake */

/* VideoCore IV analysis and ESIL, built from the cgen disassembly text.
 * Semantics follow the resim emulator, the gcc-vc4 backend and the
 * hermanhermitage notes: only cmp, cmn, btest and fcmp set flags, C is a
 * borrow after cmp, and pc relative operands are based on the address of
 * the instruction itself ($$). */

#define VC4_MAXOPS 8
#define VC4_MASK "0xffffffff"

enum {
	VC4_OP_NONE,
	VC4_OP_REG,	// r5, also "r5<<2" for addscale (shift)
	VC4_OP_IMM,	// 0x10, #16, -3
	VC4_OP_MEM,	// (rb), (rb+imm), (rb+ri<<n), (rb++), (--rb), absolute
	VC4_OP_RANGE,	// r6-r15 for ldm/stm
	VC4_OP_SAS,	// sasl N / sasr N for float conversions
};

typedef struct {
	int type;
	char reg[8];	// base register for REG, MEM, RANGE start
	char idx[8];	// index register for MEM, range end for RANGE
	int shift;	// REG shift, MEM index shift
	st64 imm;	// IMM value, MEM displacement
	double fimm;	// IMM value as a float (float ops print 0.25, 10)
	bool has_imm;
	bool postinc;
	bool predec;
	bool sasl;
	bool sasreg;	// SAS amount is a register in reg
} Vc4Operand;

typedef struct {
	char base[32];
	int cond;	// 0..15, 14 = always
	char sign[4];	// ss su us uu
	int nops;
	Vc4Operand ops[VC4_MAXOPS];
} Vc4Insn;

static const char *vc4_conds[16] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt", "gt", "le", "", "f"
};

static int vc4_cond_lookup(const char *s) {
	int i;
	if (!strcmp (s, "lo")) {
		return 2;
	}
	if (!strcmp (s, "hs")) {
		return 3;
	}
	for (i = 0; i < 16; i++) {
		if (i != 14 && !strcmp (s, vc4_conds[i])) {
			return i;
		}
	}
	return -1;
}

// map register names to the ones used in the register profile
static const char *vc4_regname(const char *s) {
	static const char *names[32] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"gp", "sp", "lr", "r27", "r28", "r29", "sr", "pc"
	};
	int i;
	for (i = 0; i < 32; i++) {
		if (!strcmp (s, names[i])) {
			return names[i];
		}
	}
	if (*s == 'r' && isdigit ((ut8)s[1])) {
		char *end = NULL;
		long n = strtol (s + 1, &end, 10);
		if (end && !*end && n >= 0 && n < 32) {
			return names[n];
		}
	}
	return NULL;
}

static int vc4_regnum(const char *s) {
	const char *n = vc4_regname (s);
	if (!n) {
		return -1;
	}
	if (*n == 'r') {
		return atoi (n + 1);
	}
	if (!strcmp (n, "gp")) {
		return 24;
	}
	if (!strcmp (n, "sp")) {
		return 25;
	}
	if (!strcmp (n, "lr")) {
		return 26;
	}
	if (!strcmp (n, "sr")) {
		return 30;
	}
	return 31; // pc
}

static bool vc4_parse_num(const char *s, st64 *out) {
	if (*s == '#') {
		s++;
	}
	const char *p = s;
	if (*p == '-' || *p == '+') {
		p++;
	}
	if (!isdigit ((ut8)*p)) {
		return false;
	}
	char *end = NULL;
	ut64 v = strtoull (p, &end, 0);
	if (!end || *end) {
		return false;
	}
	*out = (*s == '-')? -(st64)v: (st64)v;
	return true;
}

static bool vc4_parse_reg(const char *s, Vc4Operand *o) {
	char tmp[32];
	r_str_ncpy (tmp, s, sizeof (tmp));
	char *sh = strstr (tmp, "<<");
	if (sh) {
		*sh = 0;
		st64 n;
		if (!vc4_parse_num (sh + 2, &n)) {
			return false;
		}
		o->shift = (int)n;
	}
	const char *r = vc4_regname (tmp);
	if (!r) {
		return false;
	}
	o->type = VC4_OP_REG;
	r_str_ncpy (o->reg, r, sizeof (o->reg));
	return true;
}

static bool vc4_parse_mem(const char *s, Vc4Operand *o) {
	size_t len = strlen (s);
	if (len < 3 || s[0] != '(' || s[len - 1] != ')') {
		return false;
	}
	char tmp[64];
	r_str_ncpy (tmp, s + 1, R_MIN (len - 1, sizeof (tmp)));
	o->type = VC4_OP_MEM;
	char *in = tmp;
	if (r_str_startswith (in, "--")) {
		o->predec = true;
		in += 2;
	}
	size_t ilen = strlen (in);
	if (ilen > 2 && !strcmp (in + ilen - 2, "++")) {
		o->postinc = true;
		in[ilen - 2] = 0;
	}
	char *plus = strchr (in, '+');
	if (plus) {
		*plus++ = 0;
	}
	const char *r = vc4_regname (in);
	if (!r) {
		return false;
	}
	r_str_ncpy (o->reg, r, sizeof (o->reg));
	if (!plus) {
		return true;
	}
	if (vc4_parse_num (plus, &o->imm)) {
		o->has_imm = true;
		return true;
	}
	Vc4Operand ix = {0};
	if (!vc4_parse_reg (plus, &ix)) {
		return false;
	}
	r_str_ncpy (o->idx, ix.reg, sizeof (o->idx));
	o->shift = ix.shift;
	return true;
}

static bool vc4_parse_operand(const char *s, Vc4Operand *o) {
	memset (o, 0, sizeof (*o));
	if (*s == '(') {
		return vc4_parse_mem (s, o);
	}
	if (r_str_startswith (s, "sasl") || r_str_startswith (s, "sasr")) {
		o->type = VC4_OP_SAS;
		o->sasl = s[3] == 'l';
		const char *a = r_str_trim_head_ro (s + 4);
		if (vc4_parse_num (a, &o->imm)) {
			return true;
		}
		const char *r = vc4_regname (a);
		if (r) {
			o->sasreg = true;
			r_str_ncpy (o->reg, r, sizeof (o->reg));
			return true;
		}
		return false;
	}
	if (vc4_parse_num (s, &o->imm)) {
		o->type = VC4_OP_IMM;
		o->fimm = (double)o->imm;
		return true;
	}
	if (isdigit ((ut8)*s) || ((*s == '-' || *s == '+') && isdigit ((ut8)s[1]))) {
		char *end = NULL;
		o->fimm = strtod (s, &end);
		if (end && !*end) {
			o->type = VC4_OP_IMM;
			o->imm = (st64)o->fimm;
			return true;
		}
	}
	const char *dash = strchr (s, '-');
	if (dash && dash != s) {
		char a[16] = {0};
		r_str_ncpy (a, s, R_MIN ((size_t)(dash - s + 1), sizeof (a)));
		const char *ra = vc4_regname (a);
		const char *rb = vc4_regname (dash + 1);
		if (ra && rb) {
			o->type = VC4_OP_RANGE;
			r_str_ncpy (o->reg, ra, sizeof (o->reg));
			r_str_ncpy (o->idx, rb, sizeof (o->idx));
			return true;
		}
	}
	return vc4_parse_reg (s, o);
}

static bool vc4_parse(const char *text, Vc4Insn *in) {
	memset (in, 0, sizeof (*in));
	in->cond = 14;
	char *s = strdup (text);
	char *sp = strchr (s, ' ');
	char *args = NULL;
	if (sp) {
		*sp = 0;
		args = sp + 1;
	}
	// mnemonic: base[.cond][.m|.s][.ss|.su|.us|.uu]
	char *tok = s;
	char *dot = strchr (tok, '.');
	if (dot) {
		*dot = 0;
	}
	r_str_ncpy (in->base, tok, sizeof (in->base));
	while (dot) {
		tok = dot + 1;
		dot = strchr (tok, '.');
		if (dot) {
			*dot = 0;
		}
		int c = vc4_cond_lookup (tok);
		if (c >= 0) {
			in->cond = c;
		} else if (strlen (tok) == 2 && strchr ("su", tok[0]) && strchr ("su", tok[1])) {
			r_str_ncpy (in->sign, tok, sizeof (in->sign));
		}
	}
	// branches carry the condition in the mnemonic: beq, addcmpbne
	const char *bprefix = r_str_startswith (in->base, "addcmpb")? "addcmpb": "b";
	size_t blen = strlen (bprefix);
	if (r_str_startswith (in->base, bprefix) && in->base[blen]) {
		int c = vc4_cond_lookup (in->base + blen);
		if (c >= 0) {
			in->cond = c;
			in->base[blen] = 0;
		}
	}
	bool ok = true;
	if (args) {
		int depth = 0;
		char *p, *start = args;
		for (p = args; ; p++) {
			if (*p == '(') {
				depth++;
			} else if (*p == ')') {
				depth--;
			}
			if ((*p == ',' && depth == 0) || !*p) {
				bool last = !*p;
				*p = 0;
				if (in->nops >= VC4_MAXOPS || !vc4_parse_operand (r_str_trim_head_ro (start), &in->ops[in->nops])) {
					ok = false;
					break;
				}
				in->nops++;
				if (last) {
					break;
				}
				start = p + 1;
			}
		}
	}
	free (s);
	return ok;
}

/* RPN helpers, all of them take ownership of their arguments.
 * B (op, l, r) evaluates "l op r", so B ("-", a, b) is a - b */
static char *B(const char *op, char *l, char *r) {
	char *s = r_str_newf ("%s,%s,%s", r, l, op);
	free (l);
	free (r);
	return s;
}

static char *U(const char *op, char *a) {
	char *s = r_str_newf ("%s,%s", a, op);
	free (a);
	return s;
}

static char *N(ut64 n) {
	return r_str_newf ("0x%"PFMT64x, n);
}

static char *S(const char *s) {
	return strdup (s);
}

static char *M32(char *a) {
	return B ("&", a, S (VC4_MASK));
}

static char *SEXT(char *a, int bits) {
	return B ("~", a, N (bits));
}

static char *BIT(char *a, int n) {
	return B ("&", B (">>", a, N (n)), N (1));
}

static char *NOT(char *a) {
	return U ("!", a);
}

// c? a: b, where c is 0 or 1
static char *SEL(char *c, char *a, char *b) {
	char *mask = B ("-", N (0), c);
	char *bb = strdup (b);
	return B ("^", B ("&", B ("^", a, b), mask), bb);
}

// unsigned 32 bit a < b, from the borrow of the 64 bit subtraction
// (the ESIL comparison operators are signed on 32 bit registers)
static char *ULT(char *a, char *b) {
	return BIT (B ("-", a, b), 63);
}

static char *UGE(char *a, char *b) {
	return NOT (ULT (a, b));
}

static char *UGT(char *a, char *b) {
	return ULT (b, a);
}

static char *ULE(char *a, char *b) {
	return NOT (ULT (b, a));
}

// flip the sign bit so unsigned compares behave as signed ones
static char *SBIAS(char *a) {
	return B ("^", a, N (0x80000000));
}

static char *vc4_val(const Vc4Operand *o) {
	if (o->type == VC4_OP_IMM) {
		return N ((ut64)o->imm & UT32_MAX);
	}
	if (o->type == VC4_OP_REG) {
		if (!strcmp (o->reg, "pc")) {
			return S ("$$");
		}
		char *v = S (o->reg);
		return o->shift? M32 (B ("<<", v, N (o->shift))): v;
	}
	return NULL;
}

// condition evaluated on the sr flags
static char *vc4_cond_flags(int cc) {
	switch (cc) {
	case 0: return S ("zf");
	case 1: return NOT (S ("zf"));
	case 2: return S ("cf");
	case 3: return NOT (S ("cf"));
	case 4: return S ("nf");
	case 5: return NOT (S ("nf"));
	case 6: return S ("vf");
	case 7: return NOT (S ("vf"));
	case 8: return NOT (B ("|", S ("cf"), S ("zf")));
	case 9: return B ("|", S ("cf"), S ("zf"));
	case 10: return NOT (B ("^", S ("nf"), S ("vf")));
	case 11: return B ("^", S ("nf"), S ("vf"));
	case 12: return NOT (B ("|", S ("zf"), B ("^", S ("nf"), S ("vf"))));
	case 13: return B ("|", S ("zf"), B ("^", S ("nf"), S ("vf")));
	case 15: return N (0);
	}
	return N (1);
}

// condition of "cmp a, b" evaluated on the values, without touching sr
static char *vc4_cond_values(int cc, const char *a, const char *b) {
	char *r = M32 (B ("-", S (a), S (b)));
	char *n = BIT (strdup (r), 31);
	char *v = BIT (B ("&", B ("^", S (a), S (b)), B ("^", S (a), strdup (r))), 31);
	char *res = NULL;
	switch (cc) {
	case 0: res = NOT (strdup (r)); break;
	case 1: res = NOT (NOT (strdup (r))); break;
	case 2: res = ULT (S (a), S (b)); break;
	case 3: res = UGE (S (a), S (b)); break;
	case 4: res = strdup (n); break;
	case 5: res = NOT (strdup (n)); break;
	case 6: res = strdup (v); break;
	case 7: res = NOT (strdup (v)); break;
	case 8: res = UGT (S (a), S (b)); break;
	case 9: res = ULE (S (a), S (b)); break;
	case 10: res = UGE (SBIAS (S (a)), SBIAS (S (b))); break;
	case 11: res = ULT (SBIAS (S (a)), SBIAS (S (b))); break;
	case 12: res = UGT (SBIAS (S (a)), SBIAS (S (b))); break;
	case 13: res = ULE (SBIAS (S (a)), SBIAS (S (b))); break;
	case 15: res = N (0); break;
	default: res = N (1); break;
	}
	free (r);
	free (n);
	free (v);
	return res;
}

static char *SET(const char *dst, char *v) {
	return B (":=", S (dst), v);
}

static char *SEQ(char *a, char *b) {
	if (!a || !*a) {
		free (a);
		return b;
	}
	if (!b || !*b) {
		free (b);
		return a;
	}
	char *s = r_str_newf ("%s,%s", a, b);
	free (a);
	free (b);
	return s;
}

static char *vc4_flags_sub(const char *a, const char *b) {
	char *r = M32 (B ("-", S (a), S (b)));
	char *s = SET ("zf", NOT (strdup (r)));
	s = SEQ (s, SET ("nf", BIT (strdup (r), 31)));
	s = SEQ (s, SET ("cf", ULT (S (a), S (b))));
	s = SEQ (s, SET ("vf", BIT (B ("&", B ("^", S (a), S (b)), B ("^", S (a), strdup (r))), 31)));
	free (r);
	return s;
}

static char *vc4_flags_add(const char *a, const char *b) {
	char *sum = B ("+", S (a), S (b));
	char *r = M32 (strdup (sum));
	char *s = SET ("zf", NOT (strdup (r)));
	s = SEQ (s, SET ("nf", BIT (strdup (r), 31)));
	s = SEQ (s, SET ("cf", BIT (sum, 32)));
	s = SEQ (s, SET ("vf", BIT (B ("&", B ("^", B ("^", S (a), S (b)), N (UT32_MAX)), B ("^", S (a), strdup (r))), 31)));
	free (r);
	return s;
}

// shift amounts and bit numbers are taken mod 32
static char *SH(const char *b) {
	return B ("&", S (b), N (31));
}

static char *vc4_popcount(const char *x) {
	char *s = BIT (S (x), 0);
	int i;
	for (i = 1; i < 32; i++) {
		s = B ("+", s, BIT (S (x), i));
	}
	return s;
}

static char *vc4_msb(const char *x) {
	char *s = N (UT32_MAX);
	int i;
	for (i = 0; i < 32; i++) {
		s = B ("+", s, UGE (S (x), N (1ULL << i)));
	}
	return M32 (s);
}

static char *vc4_brev(const char *x) {
	char *s = N (0);
	int i;
	for (i = 0; i < 32; i++) {
		s = B ("|", s, B ("<<", BIT (S (x), i), N (31 - i)));
	}
	return s;
}

static char *F2D(const char *a) {
	return B ("F2D", S (a), N (32));
}

static char *D2F(char *a) {
	return B ("D2F", a, N (32));
}

// 2^n as a double, NULL if n is not a constant
static char *vc4_pow2(const Vc4Operand *o) {
	if (o->type != VC4_OP_SAS || o->sasreg || o->imm < -62 || o->imm > 62) {
		return NULL;
	}
	return U ("I2D", N (1ULL << R_ABS (o->imm)));
}

// integer alu result for op "name" with a and b, NULL if unknown
static char *vc4_alu(const char *name, const char *sign, const char *a, const char *b, int *type) {
	*type = R_ANAL_OP_TYPE_MOV;
	if (!strcmp (name, "mov")) {
		return S (b);
	}
	if (!strcmp (name, "add")) {
		*type = R_ANAL_OP_TYPE_ADD;
		return B ("+", S (a), S (b));
	}
	if (!strcmp (name, "sub")) {
		*type = R_ANAL_OP_TYPE_SUB;
		return B ("-", S (a), S (b));
	}
	if (!strcmp (name, "rsub")) {
		*type = R_ANAL_OP_TYPE_SUB;
		return B ("-", S (b), S (a));
	}
	if (!strcmp (name, "mul")) {
		*type = R_ANAL_OP_TYPE_MUL;
		return B ("*", S (a), S (b));
	}
	if (!strcmp (name, "and")) {
		*type = R_ANAL_OP_TYPE_AND;
		return B ("&", S (a), S (b));
	}
	if (!strcmp (name, "or")) {
		*type = R_ANAL_OP_TYPE_OR;
		return B ("|", S (a), S (b));
	}
	if (!strcmp (name, "eor")) {
		*type = R_ANAL_OP_TYPE_XOR;
		return B ("^", S (a), S (b));
	}
	if (!strcmp (name, "bic")) {
		*type = R_ANAL_OP_TYPE_AND;
		return B ("&", S (a), B ("^", S (b), N (UT32_MAX)));
	}
	if (!strcmp (name, "not")) {
		*type = R_ANAL_OP_TYPE_NOT;
		return B ("^", S (b), N (UT32_MAX));
	}
	if (!strcmp (name, "neg")) {
		*type = R_ANAL_OP_TYPE_NOT;
		return B ("-", N (0), S (b));
	}
	if (!strcmp (name, "abs")) {
		*type = R_ANAL_OP_TYPE_ABS;
		return SEL (BIT (S (b), 31), B ("-", N (0), S (b)), S (b));
	}
	if (!strcmp (name, "shl")) {
		*type = R_ANAL_OP_TYPE_SHL;
		return B ("<<", S (a), SH (b));
	}
	if (!strcmp (name, "lsr")) {
		*type = R_ANAL_OP_TYPE_SHR;
		return B (">>", S (a), SH (b));
	}
	if (!strcmp (name, "asr")) {
		*type = R_ANAL_OP_TYPE_SAR;
		return B ("ASR", SEXT (S (a), 32), SH (b));
	}
	if (!strcmp (name, "ror")) {
		*type = R_ANAL_OP_TYPE_ROR;
		return M32 (B ("|", B (">>", S (a), SH (b)), B ("<<", S (a), B ("-", N (32), SH (b)))));
	}
	if (!strcmp (name, "max") || !strcmp (name, "min")) {
		*type = R_ANAL_OP_TYPE_CMOV;
		bool max = name[1] == 'a';
		char *c = max? UGE (SBIAS (S (a)), SBIAS (S (b))): ULE (SBIAS (S (a)), SBIAS (S (b)));
		return SEL (c, S (a), S (b));
	}
	if (!strcmp (name, "bitset")) {
		*type = R_ANAL_OP_TYPE_OR;
		return B ("|", S (a), B ("<<", N (1), SH (b)));
	}
	if (!strcmp (name, "bitclear")) {
		*type = R_ANAL_OP_TYPE_AND;
		return B ("&", S (a), B ("^", B ("<<", N (1), SH (b)), N (UT32_MAX)));
	}
	if (!strcmp (name, "bitflip")) {
		*type = R_ANAL_OP_TYPE_XOR;
		return B ("^", S (a), B ("<<", N (1), SH (b)));
	}
	if (!strcmp (name, "bmask")) {
		*type = R_ANAL_OP_TYPE_AND;
		return B ("&", S (a), B ("-", B ("<<", N (1), SH (b)), N (1)));
	}
	if (!strcmp (name, "signext")) {
		*type = R_ANAL_OP_TYPE_CAST;
		return B ("~", S (a), B ("+", SH (b), N (1)));
	}
	if (!strcmp (name, "addscale")) {
		*type = R_ANAL_OP_TYPE_ADD;
		return B ("+", S (a), S (b));
	}
	if (!strcmp (name, "subscale")) {
		*type = R_ANAL_OP_TYPE_SUB;
		return B ("-", S (a), S (b));
	}
	if (!strcmp (name, "msb")) {
		return vc4_msb (b);
	}
	if (!strcmp (name, "count")) {
		return vc4_popcount (b);
	}
	if (!strcmp (name, "brev")) {
		return vc4_brev (b);
	}
	if (!strcmp (name, "adds") || !strcmp (name, "subs")) {
		bool add = name[0] == 'a';
		*type = add? R_ANAL_OP_TYPE_ADD: R_ANAL_OP_TYPE_SUB;
		char *r = M32 (B (add? "+": "-", S (a), S (b)));
		char *ovf = add
			? BIT (B ("&", B ("^", S (a), strdup (r)), B ("^", S (b), strdup (r))), 31)
			: BIT (B ("&", B ("^", S (a), S (b)), B ("^", S (a), strdup (r))), 31);
		char *sat = B ("+", N (0x7fffffff), BIT (S (a), 31));
		return SEL (ovf, sat, r);
	}
	if (!strcmp (name, "shls")) {
		*type = R_ANAL_OP_TYPE_SHL;
		char *r = M32 (B ("<<", S (a), SH (b)));
		char *back = M32 (B ("ASR", SEXT (strdup (r), 32), SH (b)));
		char *ovf = NOT (NOT (B ("^", back, S (a))));
		char *sat = B ("+", N (0x7fffffff), BIT (S (a), 31));
		return SEL (ovf, sat, r);
	}
	if (!strcmp (name, "clamp16")) {
		char *v = SBIAS (S (b));
		char *lo = SEL (ULT (strdup (v), N (0x80000000 - 0x8000)), N (0xffff8000), S (b));
		char *c = UGT (v, N (0x80000000 + 0x7fff));
		return SEL (c, N (0x7fff), lo);
	}
	if (!strcmp (name, "mulhd")) {
		*type = R_ANAL_OP_TYPE_MUL;
		char *x = (sign[0] == 's')? SEXT (S (a), 32): S (a);
		char *y = (sign[1] == 's')? SEXT (S (b), 32): S (b);
		return B (">>", B ("*", x, y), N (32));
	}
	if (!strcmp (name, "div")) {
		*type = R_ANAL_OP_TYPE_DIV;
		if (!strcmp (sign, "uu") || !*sign) {
			return B ("/", S (a), S (b));
		}
		char *x = (sign[0] == 's')? SEXT (S (a), 32): S (a);
		char *y = (sign[1] == 's')? SEXT (S (b), 32): S (b);
		return B ("~/", x, y);
	}
	return NULL;
}

// float alu result, NULL if unknown
static char *vc4_falu(const char *name, const char *a, const char *b) {
	if (!strcmp (name, "fadd")) {
		return D2F (B ("F+", F2D (a), F2D (b)));
	}
	if (!strcmp (name, "fsub")) {
		return D2F (B ("F-", F2D (a), F2D (b)));
	}
	if (!strcmp (name, "frsub")) {
		return D2F (B ("F-", F2D (b), F2D (a)));
	}
	if (!strcmp (name, "fmul")) {
		return D2F (B ("F*", F2D (a), F2D (b)));
	}
	if (!strcmp (name, "fnmul")) {
		return D2F (U ("-F", B ("F*", F2D (a), F2D (b))));
	}
	if (!strcmp (name, "fdiv")) {
		return D2F (B ("F/", F2D (a), F2D (b)));
	}
	if (!strcmp (name, "fmax")) {
		return SEL (B ("F<", F2D (a), F2D (b)), S (b), S (a));
	}
	if (!strcmp (name, "fmin")) {
		return SEL (B ("F<", F2D (b), F2D (a)), S (b), S (a));
	}
	if (!strcmp (name, "fabs")) {
		return B ("&", S (b), N (0x7fffffff));
	}
	if (!strcmp (name, "frcp")) {
		return D2F (B ("F/", U ("I2D", N (1)), F2D (b)));
	}
	if (!strcmp (name, "frsqrt")) {
		return D2F (B ("F/", U ("I2D", N (1)), U ("SQRT", F2D (b))));
	}
	if (!strcmp (name, "fceil")) {
		return D2F (U ("CEIL", F2D (b)));
	}
	if (!strcmp (name, "ffloor")) {
		return D2F (U ("FLOOR", F2D (b)));
	}
	return NULL;
}

static ut32 vc4_fbits(double d) {
	union { float f; ut32 u; } fb;
	fb.f = (float)d;
	return fb.u;
}

static int vc4_size(const char *base, bool *sext, bool *store) {
	*sext = false;
	*store = base[0] == 's';
	const char *w = base + 2;
	if (!*w) {
		return 4;
	}
	if (!strcmp (w, "h")) {
		return 2;
	}
	if (!strcmp (w, "b")) {
		return 1;
	}
	if (!strcmp (w, "sh")) {
		*sext = true;
		return 2;
	}
	if (!strcmp (w, "sb")) {
		*sext = true;
		return 1;
	}
	return 0;
}

static bool vc4_is_mem(const char *b) {
	if ((b[0] != 'l' || b[1] != 'd') && (b[0] != 's' || b[1] != 't')) {
		return false;
	}
	bool sext, store;
	return b[2] != 'm' && vc4_size (b, &sext, &store) > 0;
}

// address expression of a memory operand
static char *vc4_addr(RAnalOp *op, const Vc4Operand *m) {
	if (m->type == VC4_OP_IMM) {
		op->ptr = (ut64)m->imm & UT32_MAX;
		return N (op->ptr);
	}
	bool pc = !strcmp (m->reg, "pc");
	char *a = pc? S ("$$"): S (m->reg);
	if (*m->idx) {
		char *i = S (m->idx);
		if (m->shift) {
			i = B ("<<", i, N (m->shift));
		}
		return M32 (B ("+", a, i));
	}
	if (m->has_imm && m->imm) {
		if (pc) {
			op->ptr = (op->addr + m->imm) & UT32_MAX;
			free (a);
			return N (op->ptr);
		}
		if (!strcmp (m->reg, "sp")) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = m->imm;
		}
		return M32 (B ("+", a, N ((ut64)m->imm & UT32_MAX)));
	}
	return a;
}

static void vc4_regs_list(const Vc4Insn *in, int *regs, int *nregs, bool *extra) {
	int i;
	*nregs = 0;
	*extra = false;
	for (i = 0; i < in->nops; i++) {
		const Vc4Operand *o = &in->ops[i];
		if (o->type == VC4_OP_RANGE) {
			int a = vc4_regnum (o->reg);
			int b = vc4_regnum (o->idx);
			int n = ((b - a) & 31) + 1, j;
			for (j = 0; j < n && *nregs < 32; j++) {
				regs[(*nregs)++] = (a + j) & 31;
			}
		} else if (o->type == VC4_OP_REG) {
			if (!strcmp (o->reg, "lr") || !strcmp (o->reg, "pc")) {
				*extra = true;
			} else if (*nregs < 32) {
				regs[(*nregs)++] = vc4_regnum (o->reg);
			}
		}
	}
}

static const char *vc4_regstr(int n) {
	char tmp[8];
	snprintf (tmp, sizeof (tmp), "r%d", n);
	return vc4_regname (tmp);
}

static char *vc4_ldm_stm(RAnalOp *op, const Vc4Insn *in) {
	int regs[32], nregs, i;
	bool extra;
	vc4_regs_list (in, regs, &nregs, &extra);
	char *e = NULL;
	int total = nregs + (extra? 1: 0);
	if (!strcmp (in->base, "stm")) {
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 4 * total;
		if (extra) {
			e = SEQ (e, S ("4,sp,-=,lr,sp,=[4]"));
		}
		for (i = 0; i < nregs; i++) {
			e = SEQ (e, r_str_newf ("4,sp,-=,%s,sp,=[4]", vc4_regstr (regs[i])));
		}
		return e;
	}
	op->type = extra? R_ANAL_OP_TYPE_RET: R_ANAL_OP_TYPE_POP;
	op->stackop = R_ANAL_STACK_INC;
	op->stackptr = -4 * total;
	for (i = nregs - 1; i >= 0; i--) {
		if (regs[i] == 25) {
			e = SEQ (e, S ("4,sp,+="));
		} else {
			e = SEQ (e, r_str_newf ("sp,[4],%s,:=,4,sp,+=", vc4_regstr (regs[i])));
		}
	}
	if (extra) {
		e = SEQ (e, S ("sp,[4],pc,:=,4,sp,+="));
	}
	return e;
}

static char *vc4_mem(RAnalOp *op, const Vc4Insn *in) {
	bool sext, store;
	int size = vc4_size (in->base, &sext, &store);
	if (in->nops != 2 || in->ops[0].type != VC4_OP_REG) {
		return NULL;
	}
	const Vc4Operand *m = &in->ops[1];
	if (m->type != VC4_OP_MEM && m->type != VC4_OP_IMM) {
		return NULL;
	}
	const char *rd = in->ops[0].reg;
	op->type = store? R_ANAL_OP_TYPE_STORE: R_ANAL_OP_TYPE_LOAD;
	op->refptr = size;
	char *pre = NULL, *post = NULL;
	if (m->predec) {
		pre = r_str_newf ("%d,%s,-=", size, m->reg);
		if (!strcmp (m->reg, "sp")) {
			op->type = R_ANAL_OP_TYPE_PUSH;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = size;
		}
	} else if (m->postinc) {
		post = r_str_newf ("%d,%s,+=", size, m->reg);
		if (!strcmp (m->reg, "sp")) {
			op->type = R_ANAL_OP_TYPE_POP;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -size;
		}
	}
	char *addr = vc4_addr (op, m);
	char poke[8], peek[8];
	snprintf (poke, sizeof (poke), "=[%d]", size);
	snprintf (peek, sizeof (peek), "[%d]", size);
	char *e;
	if (store) {
		if (op->stackop == R_ANAL_STACK_GET) {
			op->stackop = R_ANAL_STACK_SET;
		}
		e = B (poke, addr, vc4_val (&in->ops[0]));
	} else {
		char *v = U (peek, addr);
		if (sext) {
			v = SEXT (v, size * 8);
		}
		e = SET (rd, v);
		if (!strcmp (rd, "pc")) {
			op->type = R_ANAL_OP_TYPE_UJMP;
			if (in->cond != 14) {
				op->type |= R_ANAL_OP_TYPE_COND;
			}
		}
	}
	return SEQ (SEQ (pre, e), post);
}

static void vc4_anal_branch(RAnalOp *op, const Vc4Insn *in, char **esil) {
	const Vc4Operand *t = &in->ops[in->nops - 1];
	op->fail = op->addr + op->size;
	if (t->type == VC4_OP_IMM) {
		op->jump = (ut64)t->imm & UT32_MAX;
	}
	if (!strcmp (in->base, "addcmpb") || (!strcmp (in->base, "b") && in->nops == 3)) {
		// addcmpb rd, add, cmp, target / b rd, cmp, target
		bool add = in->nops == 4;
		char *rd = vc4_val (&in->ops[0]);
		char *cmp = vc4_val (&in->ops[add? 2: 1]);
		op->type = R_ANAL_OP_TYPE_CJMP;
		char *e = NULL;
		if (add) {
			e = SET (in->ops[0].reg, M32 (B ("+", strdup (rd), vc4_val (&in->ops[1]))));
		}
		if (in->cond != 14) {
			char *c = vc4_cond_values (in->cond, rd, cmp);
			e = SEQ (e, r_str_newf ("%s,?{,0x%"PFMT64x",pc,:=,}", c, op->jump));
			free (c);
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			e = SEQ (e, r_str_newf ("0x%"PFMT64x",pc,:=", op->jump));
		}
		free (rd);
		free (cmp);
		*esil = e;
		return;
	}
	bool link = !strcmp (in->base, "bl") || !strcmp (in->base, "jl");
	char *target = (t->type == VC4_OP_IMM)? N (op->jump): S (t->reg);
	char *e = link? r_str_newf ("0x%"PFMT64x",lr,:=,", op->addr + op->size): strdup ("");
	char *set = SET ("pc", target);
	e = r_str_append (e, set);
	free (set);
	if (t->type == VC4_OP_IMM) {
		op->type = link? R_ANAL_OP_TYPE_CALL: R_ANAL_OP_TYPE_JMP;
	} else {
		op->type = link? R_ANAL_OP_TYPE_RCALL: R_ANAL_OP_TYPE_RJMP;
		op->reg = strdup (t->reg);
		if (!link && !strcmp (t->reg, "lr")) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
	}
	*esil = e;
	if (in->cond != 14 && in->cond != 15) {
		op->type |= R_ANAL_OP_TYPE_COND;
	}
	if (op->type == R_ANAL_OP_TYPE_JMP || op->type == R_ANAL_OP_TYPE_RJMP || op->type == R_ANAL_OP_TYPE_RET) {
		op->fail = UT64_MAX;
	}
}

static void vc4_anal(RArchSession *as, RAnalOp *op, const char *text, RArchDecodeMask mask) {
	op->jump = op->fail = op->ptr = op->val = UT64_MAX;
	if (!strcmp (text, "*unknown*")) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return;
	}
	Vc4Insn in;
	if (!vc4_parse (text, &in)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		return;
	}
	const char *base = in.base;
	char *esil = NULL;
	op->type = R_ANAL_OP_TYPE_UNK;
	if (in.cond == 15) {
		// never executed
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}
	// vector unit: opaque, only classify memory accesses
	if (base[0] == 'v' && strcmp (base, "version") && isdigit ((ut8)base[1])) {
		op->family = R_ANAL_OP_FAMILY_VEC;
		const char *k = base + 1;
		while (isdigit ((ut8)*k)) {
			k++;
		}
		if (r_str_startswith (k, "ld") || r_str_startswith (k, "memread")) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else if (r_str_startswith (k, "st") || r_str_startswith (k, "memwrite")) {
			op->type = R_ANAL_OP_TYPE_STORE;
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
		}
		return;
	}
	if (base[0] == 'v' && (base[1] == 'e' || !strcmp (base, "vgetacc") || r_str_startswith (base, "vmul") || r_str_startswith (base, "vop") || r_str_startswith (base, "vunk"))) {
		if (strcmp (base, "version")) {
			op->family = R_ANAL_OP_FAMILY_VEC;
			op->type = R_ANAL_OP_TYPE_MOV;
			return;
		}
	}
	if (!strcmp (base, "nop") || !strcmp (base, "sleep")) {
		op->type = R_ANAL_OP_TYPE_NOP;
		esil = strdup ("");
	} else if (!strcmp (base, "bkpt")) {
		op->type = R_ANAL_OP_TYPE_TRAP;
		esil = S ("TRAP");
	} else if (!strcmp (base, "swi")) {
		op->type = R_ANAL_OP_TYPE_SWI;
		if (in.nops == 1 && in.ops[0].type == VC4_OP_IMM) {
			op->val = in.ops[0].imm;
			esil = r_str_newf ("0x%"PFMT64x",$", (ut64)(0x20 + (in.ops[0].imm & 31)));
		} else if (in.nops == 1) {
			esil = r_str_newf ("0x20,%s,31,&,+,$", in.ops[0].reg);
		}
	} else if (!strcmp (base, "rts")) {
		op->type = R_ANAL_OP_TYPE_RET;
		esil = S ("lr,pc,:=");
	} else if (!strcmp (base, "rti")) {
		op->type = R_ANAL_OP_TYPE_RET;
		esil = S ("sp,[4],4,sp,+=,sp,[4],pc,:=,4,sp,+=,sr,:=");
	} else if (!strcmp (base, "ei") || !strcmp (base, "di")) {
		op->type = R_ANAL_OP_TYPE_MOV;
		esil = base[0] == 'e'? S ("0x40000000,sr,|="): S ("0xbfffffff,sr,&=");
	} else if (!strcmp (base, "user")) {
		op->type = R_ANAL_OP_TYPE_MOV;
		esil = S ("0x80000000,sr,|=");
	} else if (!strcmp (base, "cbclr")) {
		op->type = R_ANAL_OP_TYPE_MOV;
		esil = S ("0xffffffcf,sr,&=");
	} else if (r_str_startswith (base, "cbadd") && base[5]) {
		op->type = R_ANAL_OP_TYPE_ADD;
		// sr.CB (bits 5:4) += n, mod 4
		char *cb = B ("<<", B ("&", B ("+", B (">>", S ("sr"), N (4)), N (base[5] - '0')), N (3)), N (4));
		esil = SET ("sr", B ("|", B ("&", S ("sr"), N (0xffffffcf)), cb));
	} else if (!strcmp (base, "version") && in.nops == 1) {
		op->type = R_ANAL_OP_TYPE_MOV;
		esil = r_str_newf ("0x04000104,%s,:=", in.ops[0].reg);
	} else if (!strcmp (base, "tbb") || !strcmp (base, "tbh") || !strcmp (base, "switch")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
		if (in.nops == 1) {
			ut64 tbl = op->addr + op->size;
			op->ptr = tbl;
			// pc = table + 2 * signed entry, the table follows the insn
			bool half = !strcmp (base, "tbh");
			char *idx = half? B ("<<", S (in.ops[0].reg), N (1)): S (in.ops[0].reg);
			char *ent = SEXT (U (half? "[2]": "[1]", B ("+", N (tbl), idx)), half? 16: 8);
			esil = SET ("pc", M32 (B ("+", N (tbl), B ("<<", ent, N (1)))));
		}
	} else if (!strcmp (base, "b") || !strcmp (base, "bl") || !strcmp (base, "j") || !strcmp (base, "jl") || !strcmp (base, "addcmpb")) {
		if (in.nops > 0) {
			vc4_anal_branch (op, &in, &esil);
			if (strcmp (base, "addcmpb") && !(in.nops == 3) && in.cond != 14 && esil) {
				char *c = vc4_cond_flags (in.cond);
				char *w = r_str_newf ("%s,?{,%s,}", c, esil);
				free (c);
				free (esil);
				esil = w;
			}
			in.cond = 14;
		}
	} else if (!strcmp (base, "ldm") || !strcmp (base, "stm")) {
		esil = vc4_ldm_stm (op, &in);
	} else if (vc4_is_mem (base)) {
		esil = vc4_mem (op, &in);
	} else if (!strcmp (base, "lea") && in.nops == 2) {
		op->type = R_ANAL_OP_TYPE_LEA;
		const Vc4Operand *m = &in.ops[1];
		char *addr = NULL;
		if (m->type == VC4_OP_IMM) {
			op->ptr = (ut64)m->imm & UT32_MAX;
			addr = N (op->ptr);
		} else if (m->type == VC4_OP_MEM) {
			addr = vc4_addr (op, m);
			op->stackop = R_ANAL_STACK_NULL;
		}
		if (addr) {
			esil = SET (in.ops[0].reg, addr);
		}
	} else if (!strcmp (base, "cmp") || !strcmp (base, "cmn") || !strcmp (base, "btest")) {
		op->type = R_ANAL_OP_TYPE_CMP;
		if (in.nops >= 2) {
			char *a = vc4_val (&in.ops[in.nops - 2]);
			char *b = vc4_val (&in.ops[in.nops - 1]);
			if (a && b) {
				if (in.ops[in.nops - 1].type == VC4_OP_IMM) {
					op->val = in.ops[in.nops - 1].imm;
				}
				if (base[2] == 'p') {
					esil = vc4_flags_sub (a, b);
				} else if (base[2] == 'n') {
					esil = vc4_flags_add (a, b);
				} else {
					op->type = R_ANAL_OP_TYPE_ACMP;
					char *t = NOT (B ("&", B (">>", S (a), SH (b)), N (1)));
					esil = r_str_newf ("%s,DUP,zf,:=,cf,:=,0,nf,:=,0,vf,:=", t);
					free (t);
				}
			}
			free (a);
			free (b);
		}
	} else if (!strcmp (base, "fcmp")) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_FPU;
		if (in.nops >= 2) {
			const Vc4Operand *ob = &in.ops[in.nops - 1];
			char *a = vc4_val (&in.ops[in.nops - 2]);
			char *b = (ob->type == VC4_OP_IMM)? N (vc4_fbits (ob->fimm)): vc4_val (ob);
			if (a && b) {
				char *z = B ("F==", F2D (a), F2D (b));
				char *n = B ("F<", F2D (a), F2D (b));
				esil = SET ("zf", z);
				esil = SEQ (esil, SET ("nf", strdup (n)));
				esil = SEQ (esil, SET ("cf", n));
				esil = SEQ (esil, S ("0,vf,:="));
			}
			free (a);
			free (b);
		}
	} else if (in.nops >= 2 && in.ops[0].type == VC4_OP_REG) {
		// alu: op rd, b (rd = rd op b) or op rd, ra, b (rd = ra op b)
		const char *rd = in.ops[0].reg;
		const Vc4Operand *ob = &in.ops[in.nops - 1];
		bool fpu = base[0] == 'f' && strcmp (base, "floor");
		bool conv = !strcmp (base, "ftrunc") || !strcmp (base, "floor") || !strcmp (base, "flts") || !strcmp (base, "fltu");
		char *a = (in.nops == 3 && in.ops[1].type == VC4_OP_REG)? vc4_val (&in.ops[1]): S (rd);
		char *b = NULL;
		if (fpu && ob->type == VC4_OP_IMM) {
			b = N (vc4_fbits (ob->fimm));
		} else if (ob->type == VC4_OP_REG || ob->type == VC4_OP_IMM) {
			b = vc4_val (ob);
			if (ob->type == VC4_OP_IMM) {
				op->val = (ut64)ob->imm & UT32_MAX;
			}
		}
		char *res = NULL;
		int type = R_ANAL_OP_TYPE_MOV;
		if (conv && ob->type == VC4_OP_SAS) {
			op->family = R_ANAL_OP_FAMILY_FPU;
			char *p2 = vc4_pow2 (ob);
			if (p2) {
				bool neg = ob->imm < 0;
				if (r_str_startswith (base, "flt")) {
					// int to float, divided by 2^n
					char *d = (base[3] == 's')? U ("I2D", SEXT (S (a), 32)): U ("U2D", S (a));
					res = D2F (B (neg? "F*": "F/", d, p2));
				} else {
					// float to int, multiplied by 2^n
					char *d = B (neg? "F/": "F*", F2D (a), p2);
					if (!strcmp (base, "floor")) {
						d = U ("FLOOR", d);
					}
					res = M32 (U ("D2I", d));
				}
			}
			type = R_ANAL_OP_TYPE_CAST;
		} else if (b && fpu) {
			op->family = R_ANAL_OP_FAMILY_FPU;
			res = vc4_falu (base, a, b);
			type = R_ANAL_OP_TYPE_MOV;
			if (r_str_startswith (base, "fadd")) {
				type = R_ANAL_OP_TYPE_ADD;
			} else if (r_str_startswith (base, "fsub") || r_str_startswith (base, "frsub")) {
				type = R_ANAL_OP_TYPE_SUB;
			} else if (r_str_startswith (base, "fmul") || r_str_startswith (base, "fnmul")) {
				type = R_ANAL_OP_TYPE_MUL;
			} else if (r_str_startswith (base, "fdiv") || r_str_startswith (base, "frcp")) {
				type = R_ANAL_OP_TYPE_DIV;
			}
		} else if (b) {
			res = vc4_alu (base, in.sign, a, b, &type);
		}
		if (res) {
			op->type = type;
			esil = SET (rd, res);
			if (!strcmp (rd, "pc")) {
				op->type = (ob->type == VC4_OP_IMM && !strcmp (base, "mov"))? R_ANAL_OP_TYPE_JMP: R_ANAL_OP_TYPE_UJMP;
				if (op->type == R_ANAL_OP_TYPE_JMP) {
					op->jump = (ut64)ob->imm & UT32_MAX;
				}
			} else if (!strcmp (rd, "sp") && (type == R_ANAL_OP_TYPE_ADD || type == R_ANAL_OP_TYPE_SUB) && ob->type == VC4_OP_IMM && in.nops == 2) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = (type == R_ANAL_OP_TYPE_SUB)? ob->imm: -ob->imm;
			}
		} else {
			op->type = type;
		}
		free (a);
		free (b);
	}
	if (in.cond != 14 && op->type != R_ANAL_OP_TYPE_UNK) {
		op->type |= R_ANAL_OP_TYPE_COND;
		op->cond = (in.cond == 0)? R_ANAL_CONDTYPE_EQ: (in.cond == 1)? R_ANAL_CONDTYPE_NE: R_ANAL_CONDTYPE_AL;
		if (esil) {
			char *c = vc4_cond_flags (in.cond);
			char *w = r_str_newf ("%s,?{,%s,}", c, esil);
			free (c);
			free (esil);
			esil = w;
		}
	}
	if (esil && (mask & R_ARCH_OP_MASK_ESIL)) {
		r_strbuf_set (&op->esil, esil);
	}
	free (esil);
}
