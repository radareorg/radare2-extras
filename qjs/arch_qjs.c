/* radare - LGPL-3.0-only - Copyright 2026 - pancake */
#include <r_arch.h>
#include "qjs.h"

static int optype(const char *name) {
	static const struct { const char *name; int type; } types[] = {
		{ "add", R_ANAL_OP_TYPE_ADD }, { "sub", R_ANAL_OP_TYPE_SUB },
		{ "mul", R_ANAL_OP_TYPE_MUL }, { "div", R_ANAL_OP_TYPE_DIV },
		{ "mod", R_ANAL_OP_TYPE_MOD }, { "and", R_ANAL_OP_TYPE_AND },
		{ "or", R_ANAL_OP_TYPE_OR }, { "xor", R_ANAL_OP_TYPE_XOR },
		{ "shl", R_ANAL_OP_TYPE_SHL }, { "shr", R_ANAL_OP_TYPE_SAR },
		{ "sar", R_ANAL_OP_TYPE_SAR }, { "ushr", R_ANAL_OP_TYPE_SHR },
		{ "nop", R_ANAL_OP_TYPE_NOP }, { "drop", R_ANAL_OP_TYPE_POP },
		{ "throw", R_ANAL_OP_TYPE_TRAP }, { "throw_error", R_ANAL_OP_TYPE_TRAP },
		{ "ret", R_ANAL_OP_TYPE_UJMP },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (types); i++) {
		if (!strcmp (name, types[i].name)) {
			return types[i].type;
		}
	}
	if (!strncmp (name, "return", 6)) {
		return R_ANAL_OP_TYPE_RET;
	}
	if (!strncmp (name, "tail_call", 9)) {
		return R_ANAL_OP_TYPE_UJMP;
	}
	if (!strncmp (name, "call", 4) || !strcmp (name, "eval") || !strcmp (name, "apply")) {
		return R_ANAL_OP_TYPE_UCALL;
	}
	if (!strncmp (name, "push", 4)) {
		return R_ANAL_OP_TYPE_PUSH;
	}
	if (!strncmp (name, "get_", 4)) {
		return R_ANAL_OP_TYPE_LOAD;
	}
	if (!strncmp (name, "put_", 4) || !strncmp (name, "set_", 4)) {
		return R_ANAL_OP_TYPE_STORE;
	}
	return R_ANAL_OP_TYPE_UNK;
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	const QjsOpcode *o = op->size > 0? qjs_opcode (op->bytes[0]): NULL;
	if (!o || op->size < o->size) {
		op->size = 1;
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	int widths[3], label, i, pos = 1;
	int count = qjs_operands (o, widths, &label);
	op->size = o->size;
	op->type = optype (o->name);
	RStrBuf text;
	r_strbuf_init (&text);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		r_strbuf_set (&text, o->name);
	}
	for (i = 0; i < count; i++) {
		int width = abs (widths[i]);
		if ((width != 1 && width != 2 && width != 4) || pos + width > o->size) {
			r_strbuf_fini (&text);
			op->type = R_ANAL_OP_TYPE_ILL;
			return false;
		}
		st64 value = qjs_read (op->bytes + pos, widths[i], R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config));
		if (i == label) {
			op->jump = op->addr + pos + value;
			value = op->jump;
		}
		if (mask & R_ARCH_OP_MASK_DISASM) {
			if (i == label || widths[i] > 0) {
				r_strbuf_appendf (&text, "%s0x%"PFMT64x, i? ", ": " ", (ut64)value);
			} else {
				r_strbuf_appendf (&text, "%s%"PFMT64d, i? ", ": " ", value);
			}
		}
		pos += width;
	}
	if (label >= 0) {
		if (!strncmp (o->name, "goto", 4)) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else if (!strcmp (o->name, "gosub")) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->fail = op->addr + op->size;
		} else if (!strcmp (o->name, "catch")) {
			// Installing an exception handler does not branch.
			op->ptr = op->jump;
			op->jump = UT64_MAX;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = op->addr + op->size;
		}
	}
	op->eob = op->type == R_ANAL_OP_TYPE_RET || op->type == R_ANAL_OP_TYPE_UJMP || op->type == R_ANAL_OP_TYPE_TRAP;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain_nofree (&text);
	} else {
		r_strbuf_fini (&text);
	}
	return true;
}

static bool encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	char *text = strdup (op->mnemonic);
	char *arg = strchr (text, ' ');
	if (arg) {
		*arg++ = 0;
	}
	size_t code;
	bool ok = false;
	for (code = 1; code < R_ARRAY_SIZE (qjs_opcodes); code++) {
		const QjsOpcode *o = &qjs_opcodes[code];
		if (strcmp (text, o->name)) {
			continue;
		}
		ut8 bytes[256] = { code };
		int widths[3], label, pos = 1, i;
		int count = qjs_operands (o, widths, &label);
		for (i = 0; i < count; i++) {
			if (!arg || !*r_str_trim_head_ro (arg)) {
				break;
			}
			char *next = strchr (arg, ',');
			if (next) {
				*next++ = 0;
			}
			RNum *num = r_num_new (NULL, NULL, NULL);
			ut64 value = r_num_math (num, arg);
			bool valid = !num->nc.errors;
			r_num_free (num);
			int width = abs (widths[i]);
			if (!valid || (width != 1 && width != 2 && width != 4) || pos + width > o->size) {
				break;
			}
			if (i == label) {
				value -= op->addr + pos;
			}
			if (widths[i] < 0) {
				st64 limit = (st64)1 << (width * 8 - 1);
				if ((st64)value < -limit || (st64)value >= limit) {
					break;
				}
			} else if (value > ((ut64)1 << (width * 8)) - 1) {
				break;
			}
			r_write_ble (bytes + pos, value, R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config), width * 8);
			pos += width;
			arg = next;
		}
		ok = i == count && !arg && pos == o->size && r_anal_op_set_bytes (op, op->addr, bytes, o->size);
		break;
	}
	free (text);
	return ok;
}

static int info(RArchSession *s, ut32 query) {
	if (query == R_ARCH_INFO_ISVM) {
		return R_ARCH_INFO_ISVM;
	}
	if (query == R_ARCH_INFO_MAXOP_SIZE) {
		int size = 1;
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (qjs_opcodes); i++) {
			size = R_MAX (size, qjs_opcodes[i].size);
		}
		return size;
	}
	return 1;
}

static char *regs(RArchSession *s) {
	return strdup (
		"=PC pc\n=SP sp\n=BP bp\n=R0 r0\n=A0 a0\n"
		"gpr pc .32 0 0\ngpr sp .32 4 0\ngpr bp .32 8 0\ngpr r0 .32 12 0\n"
		"gpr a0 .32 16 0\n");
}

RArchPlugin r_arch_plugin_qjs = {
	.meta = { .name = "qjs", .author = "pancake", .desc = "QuickJS bytecode (build-selected VM)", .license = "LGPL-3.0-only" },
	.arch = "qjs",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_BI,
	.decode = decode,
	.encode = encode,
	.info = info,
	.regs = regs,
};

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_qjs,
	.version = R2_VERSION,
};
