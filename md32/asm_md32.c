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

static bool scq16_cpu(RAsmPluginSession *aps) {
	const char *cpu = aps && aps->rasm && aps->rasm->config? aps->rasm->config->cpu: NULL;
	return cpu && !strcmp (cpu, "scq16");
}

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

/* uSIP mnemonics: immediates carry a '#', memory operands are [base+off], [base]+, [sp+off], [#addr] */
static const Md32PseudoRule usip_rules[] = {
	{ "movi", 2, "$1 = $2" },
	{ "mov", 2, "$1 = $2" },
	{ "mov32", 2, "$1 = $2" },
	{ "lea", 2, "$1 = &$2" },
	{ "add", 2, "$1 += $2" },
	{ "add", 3, "$1 = ($2 + $3)" },
	{ "addi", 3, "$1 = ($2 + $3)" },
	{ "inc", 2, "$1 = ($2 + 1)" },
	{ "dec", 2, "$1 = ($2 - 1)" },
	{ "sub", 2, "$1 -= $2" },
	{ "sub", 3, "$1 = ($2 - $3)" },
	{ "rsub", 3, "$1 = ($3 - $2)" },
	{ "neg", 2, "$1 = -$2" },
	{ "and", 3, "$1 = ($2 & $3)" },
	{ "or", 3, "$1 = ($2 | $3)" },
	{ "xor", 2, "$1 ^= $2" },
	{ "xor", 3, "$1 = ($2 ^ $3)" },
	{ "lsl", 2, "$1 <<= $2" },
	{ "lsl", 3, "$1 = ($2 << $3)" },
	{ "lsr", 3, "$1 = ((uint32_t)$2 >> $3)" },
	{ "asr", 2, "$1 = ((int32_t)$1 >> $2)" },
	{ "asr", 3, "$1 = ((int32_t)$2 >> $3)" },
	{ "seq", 3, "$1 = ($2 == $3)" },
	{ "sle", 3, "$1 = ((int32_t)$2 <= (int32_t)$3)" },
	{ "slt", 3, "$1 = ((int32_t)$2 < (int32_t)$3)" },
	{ "sltu", 3, "$1 = ((uint32_t)$2 < (uint32_t)$3)" },
	{ "sgt", 3, "$1 = ((int32_t)$2 > (int32_t)$3)" },
	{ "cmov", 3, "$1 = ($2 != 0) ? $3 : $1" },
	{ "clz", 2, "$1 = clz32($2)" },
	{ "min", 3, "$1 = min_s32($2, $3)" },
	{ "max", 3, "$1 = max_s32($2, $3)" },
	{ "beq", 3, "if ($1 == $2) goto $3" },
	{ "bne", 3, "if ($1 != $2) goto $3" },
	{ "blt", 3, "if ((int32_t)$1 < (int32_t)$2) goto $3" },
	{ "ble", 3, "if ((int32_t)$1 <= (int32_t)$2) goto $3" },
	{ "bgt", 3, "if ((int32_t)$1 > (int32_t)$2) goto $3" },
	{ "bge", 3, "if ((int32_t)$1 >= (int32_t)$2) goto $3" },
	{ "bltu", 3, "if ((uint32_t)$1 < (uint32_t)$2) goto $3" },
	{ "bleu", 3, "if ((uint32_t)$1 <= (uint32_t)$2) goto $3" },
	{ "bgtu", 3, "if ((uint32_t)$1 > (uint32_t)$2) goto $3" },
	{ "bgeu", 3, "if ((uint32_t)$1 >= (uint32_t)$2) goto $3" },
	{ "bequ", 3, "if ((uint32_t)$1 == (uint32_t)$2) goto $3" },
	{ "bneu", 3, "if ((uint32_t)$1 != (uint32_t)$2) goto $3" },
	{ "beqz", 2, "if ($1 == 0) goto $2" },
	{ "bnez", 2, "if ($1 != 0) goto $2" },
	{ "bz", 2, "if ($1 == 0) goto $2" },
	{ "bnz", 2, "if ($1 != 0) goto $2" },
	{ "b", 1, "goto $1" },
	{ "call", 1, "$1 ()" },
	{ "ret", 0, "return" },
	{ "loop", 2, "repeat $1 times until $2" },
	{ "loop", 3, "repeat $1 times until $2 ($3)" },
	{ "loop#", 2, "repeat $1 times until $2" },
	{ "nop", 0, "nop" },
	{ "nop32", 0, "nop" },
	{ "sys", 1, "system($1)" },
	{ "save", 1, "push_callee_saved($1)" },
	{ "restore", 1, "pop_callee_saved($1)" },
	{ "jr", 1, "goto $1" },
	{ "ior", 2, "$1 = io[$2]" },
	{ "iow", 2, "io[$2] = $1" },
	{ "mfcsr", 2, "$1 = csr[$2]" },
	{ "mtcsr", 2, "csr[$1] = $2" },
	{ "ldslot", 2, "$1 = slot[$2]" },
	{ "stslot", 2, "slot[$2] = $1" },
	{ "sne", 3, "$1 = ($2 != $3)" },
	{ "scmp", 3, "$1 = cmp($2, $3)" },
	{ "movhi", 2, "$1 = $2" },
	{ "mfacc", 2, "$1 = $2" },
	{ "saturate", 2, "$1 = saturate($2)" },
	{ "bset", 3, "$1 = ($2 | (1U << $3))" },
	{ "bclr", 3, "$1 = ($2 & ~(1U << $3))" },
	{ "binv", 3, "$1 = ($2 ^ (1U << $3))" },
	{ "bext", 3, "$1 = (($2 >> $3) & 1)" },
	{ "osl", 3, "$1 = (($2 << $3) | $1)" },
	{ "extu", 4, "$1 = (($2 >> $4) & ((1 << $3) - 1))" },
	{ "fxtu", 4, "$1 = (($2 >> $4) & ((1 << $3) - 1))" },
	{ "fxts", 4, "$1 = sext($3)(($2 >> $4) & ((1 << $3) - 1))" },
	{ "fup", 4, "$1 = (($1 & ~(((1 << $3) - 1) << $4)) | (($2 & ((1 << $3) - 1)) << $4))" },
	{ "mtacc", 2, "$1 = $2" },
	{ "addi", 2, "$1 += $2" },
	{ "sext16", 2, "$1 = sext16($2)" },
	{ "zext16", 2, "$1 = ($2 & 0xffff)" },
	{ "asr16", 3, "$1 = sext16($2 << $3) >> $3" },
	{ "cop", 1, "coprocessor($1)" },
	{ "rti", 0, "return_from_interrupt" },
	{ "ieon", 0, "interrupts_on()" },
	{ "ieoff", 0, "interrupts_off()" },
	{ "idle", 0, "idle()" },
	{ "isync", 0, "isync()" },
	{ "lpexit", 0, "loop_exit()" },
	{ "trap", 0, "trap()" },
};

/* ld.w r1, [r2+0x4] -> r1 = dmem32[r2 + 0x4]; st.b r1, [r2]+ -> dmem8[r2] = r1; r2 += 1; st.abs r0, [#0xe20014] -> dmem32[0xe20014] = r0;
 * st.w [sp], #0x35 -> dmem32[sp] = 0x35 (the stores of an immediate: the memory operand comes first) */
static char *usip_memory_pseudo(const char *name, char **args, int nargs) {
	const bool load = !strncmp (name, "ld.", 3);
	if (nargs != 2 || (!load && strncmp (name, "st.", 3))) {
		return NULL;
	}
	const char w = name[3];
	const int bits = w == 'w'? 32: w == 'h'? 16: w == 'b'? 8: w == 'd'? 64: w == 'a'? 32: 0;   /* .abs: a word */
	if (!bits) {
		return NULL;
	}
	const bool sign = load && !name[4] && (w == 'h' || w == 'b');   /* ld.h / ld.b: signed; ld.w, ld.d, ld.hu, ld.bu, ld.h?...: left as is */
	if (!load && args[0][0] == '[' && args[1][0] != '[') {
		/* store of an immediate: [rB] / [sp], #imm */
		const char *close = strchr (args[0], ']');
		if (!close || close[1]) {
			return NULL;
		}
		char *inner = r_str_ndup (args[0] + 1, close - args[0] - 1);
		char *res = r_str_newf ("dmem%d[%s] = %s", bits, inner, args[1]);
		free (inner);
		return res;
	}
	const char *mem = strchr (args[1], '[');
	const char *close = mem? strchr (mem, ']'): NULL;
	if (!mem || !close || mem != args[1]) {
		return NULL;
	}
	char *inner = r_str_ndup (mem + 1, close - mem - 1);
	const bool post = close[1] == '+';
	RStrBuf *sb = r_strbuf_new ("");
	if (*inner == '#') {
		memmove (inner, inner + 1, strlen (inner));
	}
	char *plus = strchr (inner, '+');
	char *minus = strchr (inner, '-');
	if (plus) {
		*plus = 0;
		r_strbuf_setf (sb, "%s + %s", inner, plus + 1);
	} else if (minus) {
		*minus = 0;
		r_strbuf_setf (sb, "%s - %s", inner, minus + 1);
	} else {
		r_strbuf_set (sb, inner);
	}
	char *addr = r_strbuf_drain (sb);
	sb = r_strbuf_new ("");
	if (load) {
		r_strbuf_appendf (sb, "%s = %sdmem%d[%s]%s", args[0], sign? (bits == 8? "sext8(": "sext16("): "", bits, addr, sign? ")": "");
	} else {
		r_strbuf_appendf (sb, "dmem%d[%s] = %s", bits, addr, args[0]);
	}
	if (post) {
		r_strbuf_appendf (sb, "; %s += %d", inner, bits / 8);
	}
	free (addr);
	free (inner);
	return r_strbuf_drain (sb);
}

static char *usip_pseudo(const char *name, char **args, int nargs) {
	int i;
	for (i = 0; i < nargs; i++) {
		if (args[i][0] == '#') {
			args[i]++;
			/* the uncertainty marker of a count (loop#? #256?, last=...) */
			size_t len = strlen (args[i]);
			if (len > 1 && args[i][len - 1] == '?') {
				args[i][len - 1] = 0;
			}
		}
	}
	char *result = usip_memory_pseudo (name, args, nargs);
	if (result) {
		return result;
	}
	/* strip the variant suffix and the uncertainty marker: beq.d -> beq, bz.s -> bz, ret.d -> ret, add.2 -> add,
	 * bne.l -> bne, nop.ctl -> nop, lea? -> lea, call? -> call, ble.l?? -> ble, fup? -> fup, movi? -> movi */
	char base[32];
	r_str_ncpy (base, name, sizeof (base));
	char *dot = strchr (base, '.');
	if (dot) {
		*dot = 0;
	}
	size_t blen = strlen (base);
	while (blen > 1 && base[blen - 1] == '?') {
		base[--blen] = 0;
	}
	if (nargs == 1 && !strcmp (base, "addsp")) {
		/* addsp #-0x14 -> sp -= 0x14 */
		return args[0][0] == '-'? r_str_newf ("sp -= %s", args[0] + 1): r_str_newf ("sp += %s", args[0]);
	}
	if (nargs == 2 && (!strcmp (base, "ior") || !strcmp (base, "iow")) && args[1][0] == '[') {
		/* ior rB, [rA]: rA holds the port number */
		char *close = strchr (++args[1], ']');
		if (close) {
			*close = 0;
		}
	}
	size_t k;
	for (k = 0; k < R_ARRAY_SIZE (usip_rules); k++) {
		if (usip_rules[k].nargs == nargs && !strcmp (usip_rules[k].name, base)) {
			const char *text = usip_rules[k].text;
			RStrBuf *sb = r_strbuf_new ("");
			for (; *text; text++) {
				if (*text == '$' && text[1] >= '1' && text[1] <= '4') {
					r_strbuf_append (sb, args[*++text - '1']);
				} else {
					r_strbuf_append_n (sb, text, 1);
				}
			}
			return r_strbuf_drain (sb);
		}
	}
	return NULL;
}

/* SCQ16 pseudo-syntax: immediates carry a '#', memory operands are off(base), [base] += inc, [base] -= dec, off(sp);
 * a packet `{ A ‖ B }` is split by parse() into its two units.  Mnemonic suffixes .d1/.d2/.d3 (delay slots) and the provisional
 * marker '?' are stripped before the lookup. */
static const Md32PseudoRule scq16_rules[] = {
	{ "mv", 2, "$1 = $2" },
	{ "sethi", 2, "$1 = $2" },
	{ "add", 2, "$1 += $2" },
	{ "add", 3, "$1 = ($2 + $3)" },
	{ "addsp", 2, "$1 += $2" },
	{ "sub", 2, "$1 -= $2" },
	{ "sub", 3, "$1 = ($2 - $3)" },
	{ "and", 2, "$1 &= $2" },
	{ "and", 3, "$1 = ($2 & $3)" },
	{ "or", 2, "$1 |= $2" },
	{ "or", 3, "$1 = ($2 | $3)" },
	{ "xor", 3, "$1 = ($2 ^ $3)" },
	{ "mul", 2, "$1 *= $2" },
	{ "mul", 3, "$1 = ($2 * $3)" },
	{ "div", 3, "a0l = ($2 / $3); a0h = ($2 % $3)" },
	{ "sll", 3, "$1 = ($2 << $3)" },
	{ "srl", 3, "$1 = ((uint32_t)$2 >> $3)" },
	{ "sra", 3, "$1 = ((int32_t)$2 >> $3)" },
	{ "clz", 2, "$1 = clz32($2)" },
	{ "ctz", 2, "$1 = ctz32($2)" },
	{ "sqr", 2, "$1 = ($2 * $2)" },
	{ "op41.fld", 4, "$1 = (($2 << $4) | ($3 & ((1U << $4) - 1)))" },
	{ "clb", 2, "$1 = clz32((int32_t)$2 < 0 ? ~$2 : $2)" },
	{ "min", 3, "$1 = min_s32($2, $3)" },
	{ "max", 2, "$1 = max_s32($1, $2)" },
	{ "max", 3, "$1 = max_s32($2, $3)" },
	{ "cinv", 3, "$1 = ((int32_t)$2 < 0 ? -$3 : $3)" },
	{ "bclr", 3, "$1 = ($2 & ~(1U << $3))" },
	{ "bset", 2, "$1 |= (1U << $2)" },
	{ "bset", 3, "$1 = ($2 | (1U << $3))" },
	{ "btgl", 3, "$1 = ($2 ^ (1U << $3))" },
	{ "btst", 3, "$1 = (($2 >> $3) & 1)" },
	{ "xtd", 3, "$1 = sext$3($2)" },
	{ "fxtu", 4, "$1 = (($2 >> $4) & ((1U << $3) - 1))" },
	{ "fxts", 4, "$1 = sext_bits(($2 >> $4), $3)" },
	{ "fup", 4, "$1 = insert_bits($1, $2, $3, $4)" },
	{ "cmov.lt", 4, "if ((int32_t)$2 < (int32_t)$3) $1 = $4" },
	{ "cmov.ltu", 4, "if ((uint32_t)$2 < (uint32_t)$3) $1 = $4" },
	{ "cmov.eq", 4, "if ($2 == $3) $1 = $4" },
	{ "cmov.ne", 4, "if ($2 != $3) $1 = $4" },
	{ "cmov.ge", 4, "if ((int32_t)$2 >= (int32_t)$3) $1 = $4" },
	{ "cmov.leu", 4, "if ((uint32_t)$2 <= (uint32_t)$3) $1 = $4" },
	{ "cmov.le", 4, "if ((int32_t)$2 <= (int32_t)$3) $1 = $4" },
	{ "beq", 3, "if ($1 == $2) goto $3" },
	{ "bne", 3, "if ($1 != $2) goto $3" },
	{ "ble", 3, "if ((int32_t)$1 <= (int32_t)$2) goto $3" },
	{ "blt", 3, "if ((int32_t)$1 < (int32_t)$2) goto $3" },
	{ "bleu", 3, "if ((uint32_t)$1 <= (uint32_t)$2) goto $3" },
	{ "bltu", 3, "if ((uint32_t)$1 < (uint32_t)$2) goto $3" },
	{ "beqz", 3, "if ($1 == 0) goto $3" },
	{ "beqz8", 3, "if ($1 == 0) goto $3" },
	{ "bnez", 3, "if ($1 != 0) goto $3" },
	{ "bnez8", 3, "if ($1 != 0) goto $3" },
	{ "j", 1, "goto $1" },
	{ "j8", 1, "goto $1" },
	{ "j16", 1, "goto $1" },
	{ "jr", 1, "goto $1" },
	{ "jal", 1, "$1 ()" },
	{ "jal11", 1, "$1 ()" },
	{ "jalr", 1, "$1 ()" },
	{ "ior", 2, "$1 = io32[$2]" },
	{ "iow", 2, "io32[$2] = $1" },
	{ "vget", 2, "$1 = $2" },
	{ "vbcast", 2, "$1 = vbcast($2)" },
	{ "vbcast.i", 2, "$1 = vbcast($2)" },
	{ "vset.a", 2, "$1 = $2" },
	{ "vmem.set", 2, "$1 = $2" },
	{ "vins", 2, "$1 = $2" },
	{ "vrd", 2, "$1 = $2" },
	{ "vwr", 2, "$1 = $2" },
	{ "udf.rd", 2, "$1 = $2" },
	{ "udf.wr", 2, "$1 = $2" },
	{ "sys", 1, "syscall($1)" },
	{ "sys41", 1, "sys41($1)" },
	{ "vwait", 0, "vwait()" },
	{ "halt", 0, "halt()" },
	{ "ieon", 0, "interrupts_on()" },
	{ "ieoff", 0, "interrupts_off()" },
	{ "loopend", 0, "loopend()" },
	{ "nop", 0, "nop" },
};

/* lw r1, 0x4(r2) / lw.sp r1, -0x8(sp) / sw.lr lr, -0x4(sp) / lw.post r1, [r2] += 4 / sw.post r1, [r3] -= 0x10 / lbu r3, [r2] */
static char *scq16_memory_pseudo(const char *name, char **args, int nargs) {
	if (nargs != 2) {
		return NULL;
	}
	int bits = 0;
	bool sign = false;
	char base[16];
	r_str_ncpy (base, name, sizeof (base));
	char *dot = strchr (base, '.');
	if (dot) {
		*dot = 0;
	}
	const bool load = base[0] == 'l';
	if (!strcmp (base, "lb") || !strcmp (base, "lbu") || !strcmp (base, "sb")) {
		bits = 8;
		sign = !strcmp (base, "lb");
	} else if (!strcmp (base, "lh") || !strcmp (base, "lhu") || !strcmp (base, "sh")) {
		bits = 16;
		sign = !strcmp (base, "lh");
	} else if (!strcmp (base, "lw") || !strcmp (base, "sw")) {
		bits = 32;
	} else {
		return NULL;
	}
	char *mem = strdup (args[1]);
	if (!mem) {
		return NULL;
	}
	char *addr = NULL, *post = NULL;
	char postop = 0;
	if (mem[0] == '[') {
		/* [base] += inc | [base] -= dec | [base] */
		char *close = strchr (mem, ']');
		if (!close) {
			free (mem);
			return NULL;
		}
		*close = 0;
		addr = mem + 1;
		char *p = close + 1;
		r_str_trim (p);
		if (!strncmp (p, "+=", 2) || !strncmp (p, "-=", 2)) {
			postop = p[0];
			post = p + 2;
			r_str_trim (post);
		} else if (*p) {
			free (mem);
			return NULL;
		}
	} else {
		/* off(base) */
		char *open = strchr (mem, '(');
		char *close = strchr (mem, ')');
		if (!open || !close || close < open || close[1]) {
			free (mem);
			return NULL;
		}
		*open++ = 0;
		*close = 0;
		r_str_trim (mem);
		r_str_trim (open);
		RStrBuf *ab = r_strbuf_new (open);
		if (*mem && strcmp (mem, "0x0") && strcmp (mem, "0")) {
			r_strbuf_appendf (ab, " %c %s", mem[0] == '-'? '-': '+', mem[0] == '-'? mem + 1: mem);
		}
		char *a = r_strbuf_drain (ab);
		free (mem);
		mem = a;
		addr = mem;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (load) {
		r_strbuf_appendf (sb, "%s = %sdmem%d[%s]%s", args[0], sign? (bits == 8? "sext8(": "sext16("): "", bits, addr, sign? ")": "");
	} else {
		r_strbuf_appendf (sb, "dmem%d[%s] = %s", bits, addr, args[0]);
	}
	if (post) {
		r_strbuf_appendf (sb, "; %s %c= %s", addr, postop, post);
	}
	free (mem);
	return r_strbuf_drain (sb);
}

static char *scq16_pseudo(const char *name, char **args, int nargs) {
	int i;
	for (i = 0; i < nargs; i++) {
		if (args[i][0] == '#') {
			args[i]++;
		}
	}
	char base[32];
	r_str_ncpy (base, name, sizeof (base));
	size_t blen = strlen (base);
	while (blen > 1 && base[blen - 1] == '?') {
		base[--blen] = 0;
	}
	/* .d1 / .d2 / .d3 delay-slot suffixes */
	char *dot = strrchr (base, '.');
	if (dot && dot[1] == 'd' && dot[2] >= '1' && dot[2] <= '3' && !dot[3]) {
		*dot = 0;
	}
	if (!strcmp (base, "ret") || !strcmp (base, "rti")) {
		return strdup (!strcmp (base, "ret")? "return": "return_from_interrupt");
	}
	if (!strcmp (base, "do") && nargs == 2) {
		/* do r3, end=0x... (F=n) -> loop r3 times until 0x... */
		char *fin = strstr (args[1], "end=");
		char *end = fin? strchr (fin, ' '): NULL;
		if (end) {
			*end = 0;
		}
		return r_str_newf ("loop %s times until %s", args[0], fin? fin + 4: args[1]);
	}
	if (!strcmp (base, "add.sp") && nargs == 3) {
		return args[2][0] == '-'? r_str_newf ("%s = (sp - %s)", args[0], args[2] + 1): r_str_newf ("%s = (sp + %s)", args[0], args[2]);
	}
	if (!strcmp (base, "sw.isr") && nargs == 2) {
		return r_str_newf ("dmem32[sp] = %s; sp += %s", args[0], args[1] + 5);
	}
	char *result = scq16_memory_pseudo (base, args, nargs);
	if (result) {
		return result;
	}
	if (nargs == 2 && !strcmp (base, "addsp")) {
		return args[1][0] == '-'? r_str_newf ("sp -= %s", args[1] + 1): r_str_newf ("sp += %s", args[1]);
	}
	if (nargs == 2 && (!strcmp (base, "ior") || !strcmp (base, "iow"))) {
		/* ior rd, off(rb): port index rb + off */
		char *open = strchr (args[1], '(');
		char *close = strchr (args[1], ')');
		if (open && close && close > open) {
			*open = 0;
			*close = 0;
			char *port = (!strcmp (args[1], "0") || !strcmp (args[1], "0x0"))? strdup (open + 1): r_str_newf ("%s + %s", open + 1, args[1]);
			char *r = r_str_newf (!strcmp (base, "ior")? "%s = io32[%s]": "io32[%s] = %s", !strcmp (base, "ior")? args[0]: port, !strcmp (base, "ior")? port: args[0]);
			free (port);
			return r;
		}
		return NULL;
	}
	size_t k;
	for (k = 0; k < R_ARRAY_SIZE (scq16_rules); k++) {
		if (scq16_rules[k].nargs == nargs && !strcmp (scq16_rules[k].name, base)) {
			const char *text = scq16_rules[k].text;
			RStrBuf *sb = r_strbuf_new ("");
			for (; *text; text++) {
				if (*text == '$' && text[1] >= '1' && text[1] <= '4') {
					r_strbuf_append (sb, args[*++text - '1']);
				} else {
					r_strbuf_append_n (sb, text, 1);
				}
			}
			return r_strbuf_drain (sb);
		}
	}
	return NULL;
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
	if (scq16_cpu (aps)) {
		if (name[0] == '.' || !strncmp (name, "v.", 2) || !strcmp (name, "vbundle")) {
			goto fallback;
		}
		char *result = scq16_pseudo (name, args, nargs);
		if (result) {
			free (copy);
			return result;
		}
		goto fallback;
	}
	if (usip_cpu (aps)) {
		if (name[0] == '.') {
			goto fallback;
		}
		char *result = usip_pseudo (name, args, nargs);
		if (result) {
			free (copy);
			return result;
		}
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
	if (nargs == 1 && !strcmp (name, "j") && !strcmp (args[0], "r15")) {
		text = "return";
	} else if (!nargs && !strcmp (name, "ret")) {
		text = "return";
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
	if (scq16_cpu (aps)) {
		/* SCQ16 packet `{ A ‖ B }` -> parallel { a; b; }; the ESIL-style separator is U+2016 (e2 80 96) */
		const char *sep = strstr (data, " \xe2\x80\x96 ");
		if (r_str_startswith (data, "{ ") && sep) {
			const char *end = strrchr (data, '}');
			if (!end || end < sep) {
				return strdup (data);
			}
			char *left = r_str_ndup (data + 2, sep - data - 2);
			char *right = r_str_ndup (sep + 5, end - sep - 5);
			r_str_trim (left);
			r_str_trim (right);
			char *a = parse_single (aps, left);
			char *b = parse_single (aps, right);
			char *result = a && b? r_str_newf ("parallel { %s; %s; }", a, b): NULL;
			free (left);
			free (right);
			free (a);
			free (b);
			return result? result: strdup (data);
		}
		return parse_single (aps, data);
	}
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
		.desc = "MediaTek MD32 / uSIP pseudo syntax",
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
