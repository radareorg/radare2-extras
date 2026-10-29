/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include <r_asm.h>

typedef struct {
	const char *name;
	int nargs;
	const char *text;
} Md32PseudoRule;

static const Md32PseudoRule rules[] = {
	{ "mv", 2, "$1 = $2" },
	{ "mv", 3, "a0l = $2; a0h = $3" },
	{ "sethi", 2, "$1 = ($2 << 16)" },
	{ "add", 2, "$1 += $2" },
	{ "add", 3, "$1 = ($2 + $3)" },
	{ "add", 4, "$1 = ($2 + $3 + $4)" },
	{ "addsp", 2, "$1 += $2" },
	{ "sub", 2, "$1 -= $2" },
	{ "sub", 3, "$1 = ($2 - $3)" },
	{ "and", 2, "$1 &= $2" },
	{ "and", 3, "$1 = ($2 & $3)" },
	{ "or", 2, "$1 |= $2" },
	{ "or", 3, "$1 = ($2 | $3)" },
	{ "xor", 2, "$1 ^= $2" },
	{ "xor", 3, "$1 = ($2 ^ $3)" },
	{ "mul", 3, "$1 = ($2 * $3)" },
	{ "sll", 2, "$1 <<= $2" },
	{ "sll", 3, "$1 = ($2 << $3)" },
	{ "srl", 3, "$1 = ((uint32_t)$2 >> $3)" },
	{ "sra", 2, "$1 = ((int32_t)$1 >> $2)" },
	{ "sra", 3, "$1 = ((int32_t)$2 >> $3)" },
	{ "clz", 2, "$1 = clz32($2)" },
	{ "clb", 2, "$1 = clz32((int32_t)$2 < 0 ? ~$2 : $2)" },
	{ "min", 2, "$1 = min_s32($1, $2)" },
	{ "min", 3, "$1 = min_s32($2, $3)" },
	{ "max", 2, "$1 = max_s32($1, $2)" },
	{ "max", 3, "$1 = max_s32($2, $3)" },
	{ "cinv", 3, "$1 = ((int32_t)$2 < 0 ? -$3 : $3)" },
	{ "bclr", 2, "$1 &= ~(1U << $2)" },
	{ "bclr", 3, "$1 = ($2 & ~(1U << $3))" },
	{ "bset", 2, "$1 |= (1U << $2)" },
	{ "bset", 3, "$1 = ($2 | (1U << $3))" },
	{ "btgl", 2, "$1 ^= (1U << $2)" },
	{ "btgl", 3, "$1 = ($2 ^ (1U << $3))" },
	{ "beq", 3, "if ($1 == $2) goto $3" },
	{ "bne", 3, "if ($1 != $2) goto $3" },
	{ "ble", 3, "if ((int32_t)$1 <= (int32_t)$2) goto $3" },
	{ "blt", 3, "if ((int32_t)$1 < (int32_t)$2) goto $3" },
	{ "bleu", 3, "if ((uint32_t)$1 <= (uint32_t)$2) goto $3" },
	{ "bltu", 3, "if ((uint32_t)$1 < (uint32_t)$2) goto $3" },
	{ "j", 1, "goto $1" },
	{ "jal", 1, "$1 ()" },
	{ "call", 1, "$1 ()" },
	{ "swi", 1, "software_interrupt($1)" },
	{ "brk", 0, "breakpoint()" },
	{ "halt", 0, "halt()" },
	{ "nop", 0, "nop" },
};

static bool usip_cpu(RAsmPluginSession *aps) {
	const char *cpu = aps && aps->rasm && aps->rasm->config? aps->rasm->config->cpu: NULL;
	return cpu && !strcmp (cpu, "usip");
}

static char *memory_pseudo(const char *name, char **args, int nargs) {
	if (nargs != 2) {
		return NULL;
	}
	const bool load = name[0] == 'l';
	int bits = 0;
	bool sign = false;
	if (!strcmp (name, "lb") || !strcmp (name, "lbu") || !strcmp (name, "sb")) {
		bits = 8;
		sign = !strcmp (name, "lb");
	} else if (!strcmp (name, "lh") || !strcmp (name, "lhu") || !strcmp (name, "sh")) {
		bits = 16;
		sign = !strcmp (name, "lh");
	} else if (!strcmp (name, "lw") || !strcmp (name, "sw")) {
		bits = 32;
	} else {
		return NULL;
	}
	char *mem = strdup (args[1]);
	if (!mem) {
		return NULL;
	}
	char *open = strchr (mem, '(');
	char *close = strchr (mem, ')');
	if (!open || !close || close < open || close[1] || strchr (open + 1, '(')) {
		free (mem);
		return NULL;
	}
	*open++ = 0;
	*close = 0;
	char *delta = mem;
	char *base = open;
	r_str_trim (delta);
	r_str_trim (base);
	char *update = strstr (base, "+=");
	if (update) {
		if (*delta) {
			free (mem);
			return NULL;
		}
		*update = 0;
		delta = update + 2;
		r_str_trim (delta);
		r_str_trim (base);
	}
	// A load into its own updating base has unresolved hardware write ordering.
	if (!*base || (update && (!*delta || (load && !strcmp (args[0], base))))) {
		free (mem);
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (load) {
		r_strbuf_appendf (sb, "%s = %s", args[0], sign? (bits == 8? "sext8(": "sext16("): "");
	}
	r_strbuf_appendf (sb, "dmem%d[%s", bits, base);
	if (!update && *delta) {
		r_strbuf_appendf (sb, " %c %s", *delta == '-'? '-': '+', *delta == '-'? delta + 1: delta);
	}
	r_strbuf_append (sb, "]");
	if (load) {
		if (sign) {
			r_strbuf_append (sb, ")");
		}
	} else {
		r_strbuf_appendf (sb, " = %s", args[0]);
	}
	if (update) {
		r_strbuf_appendf (sb, "; %s += %s", base, delta);
	}
	free (mem);
	return r_strbuf_drain (sb);
}

static char *parse_single(RAsmPluginSession *aps, const char *data) {
	char *copy = r_str_trim_dup (data);
	if (!copy) {
		return NULL;
	}
	char *name = copy;
	char *p = name;
	while (*p && !IS_WHITESPACE (*p)) {
		p++;
	}
	if (*p) {
		*p++ = 0;
	}
	char *args[4];
	int nargs = 0;
	int depth = 0;
	char *start = p;
	for (;; p++) {
		if (*p == '(') {
			depth++;
		} else if (*p == ')' && --depth < 0) {
			goto fallback;
		}
		if (!*p || (*p == ',' && !depth)) {
			const bool end = !*p;
			*p = 0;
			char *arg = start;
			r_str_trim (arg);
			if (*arg) {
				if (nargs == R_ARRAY_SIZE (args)) {
					goto fallback;
				}
				args[nargs++] = arg;
			} else if (!end || nargs) {
				goto fallback;
			}
			if (end) {
				break;
			}
			start = p + 1;
		}
	}
	if (depth) {
		goto fallback;
	}
	// Keep delay and DSP suffixes intact. Only remove the scalar width suffix.
	const size_t len = strlen (name);
	if (len > 2 && !strcmp (name + len - 2, "16")) {
		name[len - 2] = 0;
	} else if (!strcmp (name, "mv16.l")) {
		strcpy (name, "mv");
	} else if (!strcmp (name, "nop16.l") || !strcmp (name, "nop16.r")) {
		strcpy (name, "nop");
	}
	if (!strcmp (name, "mv") && nargs == 3 && strcmp (args[0], "a0")) {
		goto fallback;
	}
	char *result = memory_pseudo (name, args, nargs);
	if (result) {
		free (copy);
		return result;
	}
	const char *text = NULL;
	if (nargs == 1 && !strcmp (name, "j") && !strcmp (args[0], "r15") && !usip_cpu (aps)) {
		text = "return";
	} else if (!nargs && !strcmp (name, "ret")) {
		text = usip_cpu (aps)? "return /* uSIP extension semantics unresolved */": "return";
	} else if (usip_cpu (aps) && nargs == 1 && name[0] == 'b' && name[1] >= '0' && name[1] <= '7' && !name[2]) {
		result = r_str_newf ("if (condition_%c) goto %s", name[1], args[0]);
		free (copy);
		return result;
	} else {
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (rules); i++) {
			if (rules[i].nargs == nargs && !strcmp (rules[i].name, name)) {
				text = rules[i].text;
				break;
			}
		}
	}
	if (text) {
		RStrBuf *sb = r_strbuf_new ("");
		for (; *text; text++) {
			if (*text == '$' && text[1] >= '1' && text[1] <= '4') {
				r_strbuf_append (sb, args[*++text - '1']);
			} else {
				r_strbuf_append_n (sb, text, 1);
			}
		}
		free (copy);
		return r_strbuf_drain (sb);
	}
fallback:
	free (copy);
	return strdup (data);
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	R_RETURN_VAL_IF_FAIL (data, NULL);
	const char *pair = strstr (data, " | ");
	if (!pair) {
		return parse_single (aps, data);
	}
	if (strstr (pair + 3, " | ")) {
		return strdup (data);
	}
	char *left = r_str_ndup (data, pair - data);
	if (!left) {
		return NULL;
	}
	char *a = parse_single (aps, left);
	char *b = parse_single (aps, pair + 3);
	char *result = a && b? r_str_newf ("parallel { %s; %s; }", a, b): NULL;
	free (left);
	free (a);
	free (b);
	return result;
}

RAsmPlugin r_asm_plugin_md32 = {
	.meta = {
		.name = "md32",
		.desc = "MediaTek MD32 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_md32,
	.version = R2_VERSION
};
#endif
