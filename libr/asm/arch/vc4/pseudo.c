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
	"bset/2/$1 |= 1 << $2",
	"bset/3/$1 = $2 | (1 << $3)",
	"bclr/2/$1 &= ~(1 << $2)",
	"bclr/3/$1 = $2 & ~(1 << $3)",
	"bchg/2/$1 ^= 1 << $2",
	"bchg/3/$1 = $2 ^ (1 << $3)",
	"btst/2/flags = $1 & (1 << $2)",
	"bmask/2/$1 &= (1 << $2) - 1",
	"bmask/3/$1 = $2 & ((1 << $3) - 1)",
	"signext/2/$1 = signext ($1, $2)",
	"signext/3/$1 = signext ($2, $3)",
	"cmp/2/flags = $1 - $2",
	"cmn/2/flags = $1 + $2",
	"lea/2/$1 = &$2",
	"ld/2/$1 = (ut32)$2",
	"ldh/2/$1 = (ut16)$2",
	"ldsh/2/$1 = (st16)$2",
	"ldb/2/$1 = (ut8)$2",
	"st/2/(ut32)$2 = $1",
	"sth/2/(ut16)$2 = $1",
	"stsh/2/(st16)$2 = $1",
	"stb/2/(ut8)$2 = $1",
	"b/1/goto $1",
	"bl/1/$1 ()",
	"addcmpb/4/$1 += $2; goto $4",
	"rts/0/return",
	"swi/1/syscall ($1)",
	"bkpt/0/breakpoint",
	"nop/0/",
	NULL
};

// condition suffix and the operator used by addcmpb<cond>
static const char *conds[][2] = {
	{ "eq", "==" }, { "ne", "!=" }, { "lt", "<" }, { "le", "<=" },
	{ "gt", ">" }, { "ge", ">=" }, { "hi", ">u" }, { "ls", "<=u" },
	{ "cs", ">=u" }, { "cc", "<u" }, { "mi", NULL }, { "pl", NULL },
	{ "vs", NULL }, { "vc", NULL }, { "f", NULL }, { NULL, NULL }
};

// "off(reg)" -> "[reg + off]", "(reg)" -> "[reg]", "#imm" -> "imm"
static char *normalize(const char *data) {
	RStrBuf *sb = r_strbuf_new ("");
	const char *p = data;
	while (*p) {
		if (*p == '#') {
			p++;
			continue;
		}
		const char *open = (*p == '(' || isalnum ((ut8)*p) || *p == '-')? strchr (p, '('): NULL;
		const char *stop = strpbrk (p, ", ");
		if (open && (!stop || open < stop)) {
			const char *close = strchr (open, ')');
			if (close) {
				char *reg = r_str_ndup (open + 1, close - open - 1);
				if (open > p) {
					char *off = r_str_ndup (p, open - p);
					r_strbuf_appendf (sb, "[%s %s %s]", reg, *off == '-'? "-": "+", *off == '-'? off + 1: off);
					free (off);
				} else {
					r_strbuf_appendf (sb, "[%s]", reg);
				}
				free (reg);
				p = close + 1;
				continue;
			}
		}
		r_strbuf_append_n (sb, p, 1);
		p++;
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

// compare and branch: "addcmpb<cond> a,b,c,dst" and "b<cond> a,b,dst"
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

static char *cmpbranch(const char *str, const char *cond, const char *op) {
	const bool never = !strcmp (cond, "f");
	char *rule = op
		? r_str_newf ("addcmpb%s/4/$1 += $2; if ($1 %s $3) goto $4", cond, op)
		: never
		? r_str_newf ("addcmpb%s/4/$1 += $2", cond)
		: r_str_newf ("addcmpb%s/4/$1 += $2; if (%s ($1 - $3)) goto $4", cond, cond);
	char *brule = op
		? r_str_newf ("b%s/3/if ($1 %s $2) goto $3", cond, op)
		: never
		? r_str_newf ("b%s/3/", cond)
		: r_str_newf ("b%s/3/if (%s ($1 - $2)) goto $3", cond, cond);
	const char *rules[] = { rule, brule, NULL };
	char *res = r_str_pseudo_transform (rules, str);
	free (rule);
	free (brule);
	return res;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *str = normalize (data);
	char *res = transform (str);
	const char *sp = strchr (str, ' ');
	size_t oplen = sp? sp - str: strlen (str);
	int i;
	// conditional forms: "addeq r4,r3,-30" -> "if (eq) r4 = r3 - 30"
	for (i = 0; !res && conds[i][0]; i++) {
		const char *cond = conds[i][0];
		size_t clen = strlen (cond);
		if (oplen <= clen || strncmp (str + oplen - clen, cond, clen)) {
			continue;
		}
		if ((oplen == clen + 7 && r_str_startswith (str, "addcmpb"))
				|| (oplen == clen + 1 && *str == 'b' && r_str_char_count (str, ',') == 2)) {
			res = cmpbranch (str, cond, conds[i][1]);
			break;
		}
		char *base = r_str_newf ("%.*s%s", (int)(oplen - clen), str, sp? sp: "");
		char *body = transform (base);
		if (body) {
			res = r_str_newf ("if (%s) %s", *cond == 'f'? "false": cond, body);
			free (body);
		}
		free (base);
	}
	free (str);
	if (!res) {
		return strdup (data);
	}
	return fix_minus (r_str_replace (res, "+= -", "-= ", 1));
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
