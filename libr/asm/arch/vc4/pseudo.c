/* radare - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	"mov/2/$1 = $2",
	"add/2/$1 += $2",
	"add/3/$1 = $2 + $3",
	"sub/2/$1 -= $2",
	"sub/3/$1 = $2 - $3",
	"rsub/2/$1 = $2 - $1",
	"rsub/3/$1 = $3 - $2",
	"mul/2/$1 *= $2",
	"mul/3/$1 = $2 * $3",
	"div/3/$1 = $2 / $3",
	"mulhd/3/$1 = ($2 * $3) >> 32",
	"and/2/$1 &= $2",
	"and/3/$1 = $2 & $3",
	"or/2/$1 |= $2",
	"or/3/$1 = $2 | $3",
	"eor/2/$1 ^= $2",
	"eor/3/$1 = $2 ^ $3",
	"bic/2/$1 &= ~$2",
	"bic/3/$1 = $2 & ~$3",
	"not/2/$1 = ~$2",
	"neg/2/$1 = -$2",
	"abs/2/$1 = abs ($2)",
	"shl/2/$1 <<= $2",
	"shl/3/$1 = $2 << $3",
	"lsr/2/$1 >>= $2",
	"lsr/3/$1 = $2 >> $3",
	"asr/2/$1 = (st32)$1 >> $2",
	"asr/3/$1 = (st32)$2 >> $3",
	"ror/2/$1 = ror ($1, $2)",
	"ror/3/$1 = ror ($2, $3)",
	"min/2/$1 = min ($1, $2)",
	"min/3/$1 = min ($2, $3)",
	"max/2/$1 = max ($1, $2)",
	"max/3/$1 = max ($2, $3)",
	"bitset/2/$1 |= 1 << $2",
	"bitset/3/$1 = $2 | (1 << $3)",
	"bitclear/2/$1 &= ~(1 << $2)",
	"bitclear/3/$1 = $2 & ~(1 << $3)",
	"bitflip/2/$1 ^= 1 << $2",
	"bitflip/3/$1 = $2 ^ (1 << $3)",
	"btest/2/flags = $1 & (1 << $2)",
	"bmask/2/$1 &= (1 << $2) - 1",
	"bmask/3/$1 = $2 & ((1 << $3) - 1)",
	"signext/2/$1 = signext ($1, $2)",
	"signext/3/$1 = signext ($2, $3)",
	"addscale/2/$1 += $2",
	"addscale/3/$1 = $2 + $3",
	"subscale/2/$1 -= $2",
	"subscale/3/$1 = $2 - $3",
	"adds/3/$1 = sat ($2 + $3)",
	"subs/3/$1 = sat ($2 - $3)",
	"msb/2/$1 = msb ($2)",
	"count/2/$1 = popcount ($2)",
	"brev/2/$1 = bitreverse ($2)",
	"clamp16/2/$1 = clamp16 ($2)",
	"cmp/2/flags = $1 - $2",
	"cmn/2/flags = $1 + $2",
	"fadd/3/$1 = $2 + $3",
	"fsub/3/$1 = $2 - $3",
	"frsub/3/$1 = $3 - $2",
	"fmul/3/$1 = $2 * $3",
	"fnmul/3/$1 = -($2 * $3)",
	"fdiv/3/$1 = $2 / $3",
	"fmax/3/$1 = fmax ($2, $3)",
	"fmin/3/$1 = fmin ($2, $3)",
	"fabs/2/$1 = fabs ($2)",
	"frcp/2/$1 = 1 / $2",
	"frsqrt/2/$1 = 1 / sqrt ($2)",
	"fceil/2/$1 = ceil ($2)",
	"ffloor/2/$1 = floor ($2)",
	"flog2/2/$1 = log2 ($2)",
	"fexp2/2/$1 = exp2 ($2)",
	"fcmp/2/flags = $1 - $2",
	"ftrunc/3/$1 = (int)($2 $3)",
	"floor/3/$1 = (int)floor ($2 $3)",
	"flts/3/$1 = (float)($2 $3)",
	"fltu/3/$1 = (float)(unsigned)($2 $3)",
	"lea/2/$1 = &$2",
	"ld/2/$1 = (ut32)$2",
	"ldh/2/$1 = (ut16)$2",
	"ldsh/2/$1 = (st16)$2",
	"ldb/2/$1 = (ut8)$2",
	"ldsb/2/$1 = (st8)$2",
	"st/2/(ut32)$2 = $1",
	"sth/2/(ut16)$2 = $1",
	"stb/2/(ut8)$2 = $1",
	"b/1/goto $1",
	"j/1/goto $1",
	"bl/1/$1 ()",
	"jl/1/$1 ()",
	"tbb/1/goto table8[$1]",
	"tbh/1/goto table16[$1]",
	"version/1/$1 = cpuid",
	"rts/0/return",
	"rti/0/return from interrupt",
	"swi/1/syscall ($1)",
	"bkpt/0/breakpoint",
	"ei/0/enable interrupts",
	"di/0/disable interrupts",
	"nop/0/",
	NULL
};

// condition suffix and the operator used by compare and branch forms
static const char *conds[][2] = {
	{ "eq", "==" }, { "ne", "!=" }, { "lt", "<" }, { "le", "<=" },
	{ "gt", ">" }, { "ge", ">=" }, { "hi", ">u" }, { "ls", "<=u" },
	{ "cs", "<u" }, { "lo", "<u" }, { "cc", ">=u" }, { "hs", ">=u" },
	{ "mi", NULL }, { "pl", NULL }, { "vs", NULL }, { "vc", NULL },
	{ "f", NULL }, { NULL, NULL }
};

static int cond_index(const char *s) {
	int i;
	for (i = 0; conds[i][0]; i++) {
		if (!strcmp (s, conds[i][0])) {
			return i;
		}
	}
	return -1;
}

// "(r1+8)" -> "[r1 + 8]", "(r1)" -> "[r1]", "#imm" -> "imm"
static char *normalize(const char *data) {
	RStrBuf *sb = r_strbuf_new ("");
	const char *p;
	for (p = data; *p; p++) {
		if (*p == '#') {
			continue;
		}
		if (*p == '(' && p > data && (p[-1] == ',' || p[-1] == ' ')) {
			const char *close = strchr (p, ')');
			if (close) {
				char *in = r_str_ndup (p + 1, close - p - 1);
				in = r_str_replace (in, "+-", " - ", 1);
				in = r_str_replace (in, "+", " + ", 1);
				in = r_str_replace (in, " +  + ", "++", 1);
				r_strbuf_appendf (sb, "[%s]", in);
				free (in);
				p = close;
				continue;
			}
		}
		r_strbuf_append_n (sb, p, 1);
	}
	return r_strbuf_drain (sb);
}

static char *transform(const char *data) {
	char *res = r_str_pseudo_transform (pseudo_rules, data);
	if (res && strcmp (res, data)) {
		return res;
	}
	free (res);
	return NULL;
}

// "addcmpb<cond> a,b,c,dst" and "b<cond> a,b,dst" compare after the add
static char *cmpbranch(const char *str, const char *cond, const char *op, bool add) {
	char *rule;
	if (!strcmp (cond, "f")) {
		rule = add? strdup ("x/4/$1 += $2"): strdup ("x/3/");
	} else if (add) {
		rule = op? r_str_newf ("x/4/$1 += $2; if ($1 %s $3) goto $4", op)
			: r_str_newf ("x/4/$1 += $2; if (%s ($1 - $3)) goto $4", cond);
	} else {
		rule = op? r_str_newf ("x/3/if ($1 %s $2) goto $3", op)
			: r_str_newf ("x/3/if (%s ($1 - $2)) goto $3", cond);
	}
	const char *rules[] = { rule, NULL };
	const char *args = strchr (str, ' ');
	char *s = r_str_newf ("x%s", args? args: "");
	char *res = r_str_pseudo_transform (rules, s);
	free (s);
	free (rule);
	return res;
}

// r_str_pseudo_transform turns "a + -1" into "a -1", make it "a - 1"
static char *fix_minus(char *s) {
	RStrBuf *sb = r_strbuf_new ("");
	char *p;
	for (p = s; *p; p++) {
		r_strbuf_append_n (sb, p, 1);
		if (p > s && p[0] == ' ' && p[1] == '-' && isdigit ((ut8)p[2]) && isalnum ((ut8)p[-1])) {
			r_strbuf_append (sb, "- ");
			p++;
		}
	}
	free (s);
	return r_strbuf_drain (sb);
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *str = normalize (data);
	char *sp = strchr (str, ' ');
	char *args = sp? sp: "";
	char *mn = r_str_ndup (str, sp? sp - str: strlen (str));
	// mnemonic: base[.cond][.m|.s][.ss|.su|.us|.uu]
	int cond = -1;
	char *dot = strchr (mn, '.');
	if (dot) {
		char *t = dot;
		*dot = 0;
		while (t) {
			char *part = t + 1;
			t = strchr (part, '.');
			if (t) {
				*t = 0;
			}
			int c = cond_index (part);
			if (c >= 0) {
				cond = c;
			}
		}
	}
	char *res = NULL;
	int ci = -1;
	int nargs = *args? (int)r_str_char_count (args, ',') + 1: 0;
	if (r_str_startswith (mn, "addcmpb")) {
		ci = mn[7]? cond_index (mn + 7): -1;
		if (!mn[7]) {
			char *s = r_str_newf ("x%s", args);
			const char *rules[] = { "x/4/$1 += $2; goto $4", NULL };
			res = r_str_pseudo_transform (rules, s);
			free (s);
		} else if (ci >= 0) {
			res = cmpbranch (str, conds[ci][0], conds[ci][1], true);
		}
	} else if (mn[0] == 'b' && mn[1] && (ci = cond_index (mn + 1)) >= 0) {
		if (nargs == 3) {
			res = cmpbranch (str, conds[ci][0], conds[ci][1], false);
		} else if (strcmp (conds[ci][0], "f")) {
			res = r_str_newf ("if (%s) goto%s", conds[ci][0], args);
		}
	} else if (!strcmp (mn, "ldm") || !strcmp (mn, "stm")) {
		// ldm r6-r7,pc,(sp++) / stm r6-r7,lr,(--sp)
		char *regs = r_str_trim_dup (args);
		char *last = (char *)r_str_rchr (regs, NULL, ',');
		if (last) {
			*last = 0;
		}
		bool ret = strstr (regs, ",pc") || !strcmp (regs, "pc");
		res = r_str_newf ("%s %s%s", (*mn == 'l')? "pop": "push", regs, ret? "; return": "");
		free (regs);
	} else {
		char *s = r_str_newf ("%s%s", mn, args);
		char *body = transform (s);
		free (s);
		if (body) {
			if (cond >= 0 && strcmp (conds[cond][0], "f")) {
				res = r_str_newf ("if (%s) %s", conds[cond][0], body);
				free (body);
			} else if (cond >= 0) {
				free (body);
			} else {
				res = body;
			}
		}
	}
	free (mn);
	free (str);
	if (!res) {
		return strdup (data);
	}
	res = r_str_replace (res, "+= -", "-= ", 1);
	return fix_minus (res);
}

RAsmPlugin r_asm_plugin_vc4 = {
	.meta = {
		.name = "vc4",
		.desc = "VideoCore IV pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_vc4,
	.version = R2_VERSION
};
#endif
