/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* Pseudo syntax for the MN10300 / AM33 disassembly: `mov d0, (0x8, a2)` becomes `[a2 + 0x8] = d0`.
 * Display only; the operand order of the ISA is source first, destination last. */

#include <r_asm.h>

typedef struct {
	const char *name;
	int nargs;
	const char *text;
} Mn103PseudoRule;

static const Mn103PseudoRule rules[] = {
	{ "mov", 2, "$2 = $1" },
	{ "movu", 2, "$2 = $1" },
	{ "movbu", 2, "$2 = (uint8_t) $1" },
	{ "movhu", 2, "$2 = (uint16_t) $1" },
	{ "fmov", 2, "$2 = $1" },
	{ "clr", 1, "$1 = 0" },
	{ "add", 2, "$2 += $1" },
	{ "add", 3, "$3 = $2 + $1" },
	{ "addc", 2, "$2 += $1 + cf" },
	{ "sub", 2, "$2 -= $1" },
	{ "sub", 3, "$3 = $2 - $1" },
	{ "subc", 2, "$2 -= $1 + cf" },
	{ "inc", 1, "$1++" },
	{ "inc4", 1, "$1 += 4" },
	{ "cmp", 2, "cmp $2, $1" },
	{ "and", 2, "$2 &= $1" },
	{ "and", 3, "$3 = $2 & $1" },
	{ "or", 2, "$2 |= $1" },
	{ "or", 3, "$3 = $2 | $1" },
	{ "xor", 2, "$2 ^= $1" },
	{ "xor", 3, "$3 = $2 ^ $1" },
	{ "not", 1, "$1 = ~$1" },
	{ "asl", 2, "$2 <<= $1" },
	{ "asl", 3, "$3 = $2 << $1" },
	{ "asl2", 1, "$1 <<= 2" },
	{ "asr", 2, "$2 >>= $1" },
	{ "asr", 3, "$3 = $2 >> $1" },
	{ "lsr", 2, "$2 = (uint32_t) $2 >> $1" },
	{ "lsr", 3, "$3 = (uint32_t) $2 >> $1" },
	{ "rol", 1, "$1 = rol($1, 1)" },
	{ "ror", 1, "$1 = ror($1, 1)" },
	{ "mul", 2, "mdr:$2 = $2 * $1" },
	{ "mulu", 2, "mdr:$2 = (uint32_t) $2 * $1" },
	{ "mulq", 2, "$2 *= $1" },
	{ "mulqu", 2, "$2 = (uint32_t) $2 * $1" },
	{ "div", 2, "$2 = mdr:$2 / $1" },
	{ "divu", 2, "$2 = (uint32_t) mdr:$2 / $1" },
	{ "ext", 1, "mdr = $1 < 0 ? -1 : 0" },
	{ "extb", 1, "$1 = (int8_t) $1" },
	{ "extbu", 1, "$1 = (uint8_t) $1" },
	{ "exth", 1, "$1 = (int16_t) $1" },
	{ "exthu", 1, "$1 = (uint16_t) $1" },
	{ "btst", 2, "test $2 & $1" },
	{ "bset", 2, "$2 |= $1" },
	{ "bclr", 2, "$2 &= ~$1" },
	{ "swap", 2, "$2 = bswap32($1)" },
	{ "swaph", 2, "$2 = bswap16x2($1)" },
	{ "bra", 1, "goto $1" },
	{ "beq", 1, "if (==) goto $1" },
	{ "bne", 1, "if (!=) goto $1" },
	{ "bgt", 1, "if (>) goto $1" },
	{ "bge", 1, "if (>=) goto $1" },
	{ "ble", 1, "if (<=) goto $1" },
	{ "blt", 1, "if (<) goto $1" },
	{ "bhi", 1, "if (u>) goto $1" },
	{ "bcc", 1, "if (u>=) goto $1" },
	{ "bls", 1, "if (u<=) goto $1" },
	{ "bcs", 1, "if (u<) goto $1" },
	{ "bvc", 1, "if (!overflow) goto $1" },
	{ "bvs", 1, "if (overflow) goto $1" },
	{ "bnc", 1, "if (!negative) goto $1" },
	{ "bns", 1, "if (negative) goto $1" },
	{ "lra", 0, "goto lar" },
	{ "leq", 0, "if (==) goto lar" },
	{ "lne", 0, "if (!=) goto lar" },
	{ "lgt", 0, "if (>) goto lar" },
	{ "lge", 0, "if (>=) goto lar" },
	{ "lle", 0, "if (<=) goto lar" },
	{ "llt", 0, "if (<) goto lar" },
	{ "lhi", 0, "if (u>) goto lar" },
	{ "lcc", 0, "if (u>=) goto lar" },
	{ "lls", 0, "if (u<=) goto lar" },
	{ "lcs", 0, "if (u<) goto lar" },
	{ "setlb", 0, "lar = next" },
	{ "jmp", 1, "goto $1" },
	{ "call", 3, "call $1 (save $2, frame $3)" },
	{ "calls", 1, "call $1" },
	{ "ret", 2, "return (restore $1, frame $2)" },
	{ "retf", 2, "return mdr (restore $1, frame $2)" },
	{ "rets", 0, "return" },
	{ "rti", 0, "return from interrupt" },
	{ "movm", 2, "$2 = $1" },
	{ "nop", 0, "" },
	{ "trap", 0, "trap" },
	{ "syscall", 0, "syscall" },
	{ "syscall", 1, "syscall $1" },
};

/* `(0x8, a2)` -> `[a2 + 0x8]`, `(a0)` -> `[a0]`, `(0x8070)` -> `[0x8070]`, `(d1, a0)` -> `[a0 + d1]` */
static char *memory_text(const char *arg) {
	size_t len = strlen (arg);
	if (len < 3 || arg[0] != '(' || arg[len - 1] != ')') {
		return strdup (arg);
	}
	char *inner = r_str_ndup (arg + 1, len - 2);
	if (!inner) {
		return NULL;
	}
	char *comma = strstr (inner, ", ");
	char *result;
	if (!comma) {
		if (r_str_endswith (inner, "+")) {
			inner[strlen (inner) - 1] = 0;
			result = r_str_newf ("[%s++]", inner);
		} else {
			result = r_str_newf ("[%s]", inner);
		}
	} else {
		*comma = 0;
		const char *first = inner;
		const char *second = comma + 2;
		if (r_str_endswith (first, "+")) {
			result = r_str_newf ("[%s] (%s += %s)", first, first, second);
		} else if (first[0] == '-') {
			result = r_str_newf ("[%s - %s]", second, first + 1);
		} else {
			result = r_str_newf ("[%s + %s]", second, first);
		}
	}
	free (inner);
	return result;
}

/* split "mnemonic a, (b, c), d" into mnemonic and top-level arguments */
static int split_args(char *text, char **mnemonic, char **args, int max) {
	char *p = text;
	while (*p && *p != ' ') {
		p++;
	}
	*mnemonic = text;
	if (*p) {
		*p++ = 0;
	}
	int n = 0;
	while (*p && n < max) {
		while (*p == ' ') {
			p++;
		}
		char *start = p;
		int depth = 0;
		while (*p) {
			if (*p == '(' || *p == '[') {
				depth++;
			} else if (*p == ')' || *p == ']') {
				depth--;
			} else if (*p == ',' && depth == 0) {
				break;
			}
			p++;
		}
		if (*p == ',') {
			*p++ = 0;
		}
		r_str_trim (start);
		if (*start) {
			args[n++] = start;
		}
	}
	return n;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *text = strdup (data);
	if (!text) {
		return NULL;
	}
	char *mnemonic = NULL;
	char *args[6] = { 0 };
	const int nargs = split_args (text, &mnemonic, args, 6);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (rules); i++) {
		const Mn103PseudoRule *rule = &rules[i];
		if (strcmp (rule->name, mnemonic) || rule->nargs != nargs) {
			continue;
		}
		RStrBuf *sb = r_strbuf_new ("");
		const char *t = rule->text;
		while (*t) {
			if (t[0] == '$' && t[1] >= '1' && t[1] <= '6' && t[1] - '1' < nargs) {
				char *m = memory_text (args[t[1] - '1']);
				r_strbuf_append (sb, m? m: "");
				free (m);
				t += 2;
			} else {
				r_strbuf_append_n (sb, t, 1);
				t++;
			}
		}
		free (text);
		return r_strbuf_drain (sb);
	}
	free (text);
	return strdup (data);
}

RAsmPlugin r_asm_plugin_mn103 = {
	.meta = {
		.name = "mn103",
		.desc = "Panasonic MN10300 / AM33 pseudo syntax",
		.author = "n0p",
		.license = "GPL-3.0-or-later",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mn103,
	.version = R2_VERSION
};
#endif
