/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include <r_arch.h>

typedef struct {
	unsigned type;
	int shift;
} Md32Argument;

typedef struct {
	const char *name;
	ut32 opcode;
	ut32 mask;
	ut8 group;
	ut8 format;
	ut8 nargs;
	Md32Argument args[4];
} Md32Opcode;

static st32 md32_sign(ut32 value, unsigned bits) {
	const ut32 sign = 1U << (bits - 1);
	return (st32)(value & (sign - 1)) - (st32)(value & sign);
}

#include "md32_opcodes.h"

static const char *const gpregs[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

typedef struct {
	const char *reg;
	st32 value;
} Md32Operand;

typedef struct {
	const Md32Opcode *desc;
	Md32Operand args[4];
} Md32Insn;

static bool decode_insn(Md32Insn *insn, ut32 word, unsigned group) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (md32_opcodes); i++) {
		const Md32Opcode *desc = &md32_opcodes[i];
		if (desc->group != group || (word & desc->mask) != desc->opcode) {
			continue;
		}
		insn->desc = desc;
		unsigned j;
		for (j = 0; j < desc->nargs; j++) {
			const Md32Argument *arg = &desc->args[j];
			Md32Operand *out = &insn->args[j];
			out->value = md32_argument_value (arg->type, word, arg->shift);
			out->reg = md32_argument_register (arg->type);
			if (arg->type == MD32_R_C3U || arg->type == MD32_R_C4U) {
				out->reg = gpregs[out->value];
			}
		}
		return true;
	}
	return false;
}

static void append_arg(RStrBuf *sb, const Md32Operand *arg) {
	if (arg->reg) {
		r_strbuf_append (sb, arg->reg);
	} else if (arg->value < 0) {
		r_strbuf_appendf (sb, "-0x%x", (ut32)(-(st64)arg->value));
	} else {
		r_strbuf_appendf (sb, "0x%x", (ut32)arg->value);
	}
}

static bool is_name(const Md32Insn *insn, const char *name) {
	const size_t len = strlen (name);
	const char *mn = insn->desc->name;
	return !strncmp (mn, name, len) && (!mn[len] || mn[len] == '.' || !strcmp (mn + len, "16")
		|| !strncmp (mn + len, "16.", 3));
}

static bool is_branch(const Md32Insn *insn) {
	return is_name (insn, "beq") || is_name (insn, "bne") || is_name (insn, "ble")
		|| is_name (insn, "bleu") || is_name (insn, "blt") || is_name (insn, "bltu");
}

static bool is_flow(const Md32Insn *insn) {
	return is_branch (insn) || is_name (insn, "j") || is_name (insn, "jal");
}

static ut64 relative_target(ut64 addr, st32 displacement) {
	return (ut32)((ut32)addr + (ut32)displacement);
}

static void format_insn(RStrBuf *sb, const Md32Insn *insn, ut64 addr) {
	const Md32Opcode *d = insn->desc;
	unsigned i;
	r_strbuf_append (sb, d->name);
	for (i = 0; i < d->nargs; i++) {
		const Md32Operand *arg = &insn->args[i];
		if (!i) {
			r_strbuf_append (sb, " ");
		} else if (d->format == 1 && i == 2) {
			r_strbuf_append (sb, "(");
		} else if (d->format == 3 && i == 2) {
			r_strbuf_append (sb, "+=");
		} else {
			r_strbuf_append (sb, ", ");
		}
		if ((d->format == 3 && i == 1) || (d->format == 2 && i + 1 == d->nargs)) {
			r_strbuf_append (sb, "(");
		}
		if (i + 1 == d->nargs && !arg->reg && (is_flow (insn) || is_name (insn, "do"))) {
			r_strbuf_appendf (sb, "0x%08"PFMT64x, relative_target (addr, arg->value));
		} else {
			append_arg (sb, arg);
		}
		if ((d->format == 1 || d->format == 2 || d->format == 3) && i + 1 == d->nargs) {
			r_strbuf_append (sb, ")");
		}
	}
}

static int insn_type(const Md32Insn *insn) {
	if (is_branch (insn)) {
		return R_ANAL_OP_TYPE_CJMP;
	}
	if (is_name (insn, "jal")) {
		return insn->args[0].reg? R_ANAL_OP_TYPE_RCALL: R_ANAL_OP_TYPE_CALL;
	}
	if (is_name (insn, "j")) {
		const char *reg = insn->args[0].reg;
		return !reg? R_ANAL_OP_TYPE_JMP: !strcmp (reg, "r15")? R_ANAL_OP_TYPE_RET: R_ANAL_OP_TYPE_RJMP;
	}
	if (is_name (insn, "rti")) {
		return R_ANAL_OP_TYPE_RET;
	}
	if (is_name (insn, "nop")) {
		return R_ANAL_OP_TYPE_NOP;
	}
	if (is_name (insn, "brk") || is_name (insn, "halt")) {
		return R_ANAL_OP_TYPE_TRAP;
	}
	if (is_name (insn, "swi")) {
		return R_ANAL_OP_TYPE_SWI;
	}
	if (is_name (insn, "add") || is_name (insn, "addx") || is_name (insn, "addsp")) {
		return R_ANAL_OP_TYPE_ADD;
	}
	if (is_name (insn, "sub") || is_name (insn, "subx")) {
		return R_ANAL_OP_TYPE_SUB;
	}
	if (is_name (insn, "and") || is_name (insn, "bclr")) {
		return R_ANAL_OP_TYPE_AND;
	}
	if (is_name (insn, "or") || is_name (insn, "bset")) {
		return R_ANAL_OP_TYPE_OR;
	}
	if (is_name (insn, "xor") || is_name (insn, "btgl")) {
		return R_ANAL_OP_TYPE_XOR;
	}
	if (is_name (insn, "sll")) {
		return R_ANAL_OP_TYPE_SHL;
	}
	if (is_name (insn, "srl")) {
		return R_ANAL_OP_TYPE_SHR;
	}
	if (is_name (insn, "sra")) {
		return R_ANAL_OP_TYPE_SAR;
	}
	if (is_name (insn, "rol")) {
		return R_ANAL_OP_TYPE_ROL;
	}
	if (is_name (insn, "ror")) {
		return R_ANAL_OP_TYPE_ROR;
	}
	if (is_name (insn, "mul") || is_name (insn, "mac")) {
		return R_ANAL_OP_TYPE_MUL;
	}
	if (is_name (insn, "udiv") || is_name (insn, "sdiv")) {
		return R_ANAL_OP_TYPE_DIV;
	}
	if (is_name (insn, "lb") || is_name (insn, "lbu") || is_name (insn, "lh")
		|| is_name (insn, "lhu") || is_name (insn, "lw")) {
		return R_ANAL_OP_TYPE_LOAD;
	}
	if (is_name (insn, "sb") || is_name (insn, "sh") || is_name (insn, "sw")) {
		return R_ANAL_OP_TYPE_STORE;
	}
	if (is_name (insn, "ior")) {
		return R_ANAL_OP_TYPE_IO;
	}
	if (is_name (insn, "iow")) {
		return R_ANAL_OP_TYPE_IO;
	}
	if (is_name (insn, "mv") || is_name (insn, "sethi")) {
		return R_ANAL_OP_TYPE_MOV;
	}
	return R_ANAL_OP_TYPE_UNK;
}

static void analyze_insn(RAnalOp *op, const Md32Insn *insn) {
	const Md32Opcode *d = insn->desc;
	const Md32Operand *last = d->nargs? &insn->args[d->nargs - 1]: NULL;
	op->type = insn_type (insn);
	if (is_flow (insn)) {
		op->delay = strstr (d->name, ".d2")? 2: strstr (d->name, ".d1")? 1: 0;
		if (last && !last->reg) {
			op->jump = relative_target (op->addr, last->value);
		}
		if (is_branch (insn)) {
			op->cond = is_name (insn, "beq")? R_ANAL_CONDTYPE_EQ:
				is_name (insn, "bne")? R_ANAL_CONDTYPE_NE:
				is_name (insn, "bleu")? R_ANAL_CONDTYPE_LS:
				is_name (insn, "bltu")? R_ANAL_CONDTYPE_LO:
				is_name (insn, "ble")? R_ANAL_CONDTYPE_LE: R_ANAL_CONDTYPE_LT;
			op->sign = is_name (insn, "ble") || is_name (insn, "blt");
		}
		if (is_branch (insn) || is_name (insn, "jal")) {
			op->fail = relative_target (op->addr, op->size);
		}
		op->eob = !is_name (insn, "jal");
		if (last && last->reg) {
			op->reg = last->reg;
		}
	} else if (is_name (insn, "do") && last) {
		// Loop setup does not branch. The back edge is at the loop end.
		op->ptr = relative_target (op->addr, last->value);
		op->direction = R_ANAL_OP_DIR_REF;
	} else if (last && !last->reg) {
		op->val = is_name (insn, "sethi")? (ut32)last->value << 16: (ut32)last->value;
	}
	if (is_name (insn, "rti")) {
		op->eob = true;
		op->reg = "ipc";
	}
	if (op->type == R_ANAL_OP_TYPE_LOAD || op->type == R_ANAL_OP_TYPE_STORE) {
		op->refptr = is_name (insn, "lw") || is_name (insn, "sw")? 4:
			is_name (insn, "lh") || is_name (insn, "lhu") || is_name (insn, "sh")? 2: 1;
		op->ptrsize = op->refptr;
		op->sign = is_name (insn, "lh") || is_name (insn, "lb");
		op->direction = op->type == R_ANAL_OP_TYPE_LOAD? R_ANAL_OP_DIR_READ: R_ANAL_OP_DIR_WRITE;
		const unsigned base = d->format == 3? 1: 2;
		const unsigned delta = d->format == 3? 2: 1;
		op->ireg = insn->args[base].reg;
		op->disp = d->format == 3? 0: insn->args[delta].value;
		if (op->ireg && !strcmp (op->ireg, "r14")) {
			op->stackop = op->type == R_ANAL_OP_TYPE_LOAD? R_ANAL_STACK_GET: R_ANAL_STACK_SET;
		}
	}
}

static void esil_arg(RStrBuf *sb, const Md32Operand *arg) {
	if (arg->reg) {
		r_strbuf_append (sb, arg->reg);
	} else {
		r_strbuf_appendf (sb, "0x%x", (ut32)arg->value);
	}
}

static void insn_esil(RAnalOp *op, const Md32Insn *insn) {
	const Md32Opcode *d = insn->desc;
	const Md32Operand *a = insn->args;
	RStrBuf *sb = &op->esil;
	// Carry, saturation, delayed control flow, and hardware loops need more
	// state than their integer result. Leave their ESIL explicitly absent.
	if (op->delay || is_name (insn, "do") || is_name (insn, "addx")
		|| is_name (insn, "subx")) {
		return;
	}
	if (is_name (insn, "mv")) {
		if (d->nargs == 3) {
			r_strbuf_setf (sb, "%s,a0l,=,%s,a0h,=", a[1].reg, a[2].reg);
		} else {
			esil_arg (sb, &a[1]);
			r_strbuf_appendf (sb, ",%s,=", a[0].reg);
		}
	} else if (is_name (insn, "sethi")) {
		r_strbuf_setf (sb, "0x%x,%s,=", (ut32)a[1].value << 16, a[0].reg);
	} else if (is_name (insn, "clz")) {
		r_strbuf_setf (sb, "32,%s,CLZ,%s,=", a[1].reg, a[0].reg);
	} else if (is_name (insn, "clb")) {
		r_strbuf_setf (sb, "32,%s,DUP,31,SWAP,>>,?{,0xffffffff,^,},CLZ,%s,=", a[1].reg, a[0].reg);
	} else if (is_name (insn, "cinv")) {
		r_strbuf_setf (sb, "31,%s,>>,?{,%s,0,-,}{,%s,},%s,=", a[1].reg, a[2].reg, a[2].reg, a[0].reg);
	} else if (is_name (insn, "max") || is_name (insn, "min")) {
		const char *lhs = a[d->nargs == 2? 0: 1].reg;
		const char *rhs = a[d->nargs == 2? 1: 2].reg;
		r_strbuf_setf (sb, "32,%s,~,32,%s,~,%s,?{,%s,}{,%s,},%s,=",
			rhs, lhs, is_name (insn, "max")? ">=": "<=", lhs, rhs, a[0].reg);
	} else if (is_branch (insn)) {
		const bool equality = is_name (insn, "beq") || is_name (insn, "bne");
		esil_arg (sb, &a[1]);
		if (!equality) {
			r_strbuf_append (sb, op->sign? ",32,SWAP,~": ",0,+");
		}
		r_strbuf_append (sb, ",");
		esil_arg (sb, &a[0]);
		if (!equality) {
			r_strbuf_append (sb, op->sign? ",32,SWAP,~": ",0,+");
		}
		if (equality) {
			r_strbuf_append (sb, is_name (insn, "beq")? ",==,$z": ",==,$z,!");
		} else {
			r_strbuf_append (sb, is_name (insn, "ble") || is_name (insn, "bleu")? ",<=": ",<");
		}
		r_strbuf_appendf (sb, ",?{,0x%08"PFMT64x",pc,=,}", op->jump);
	} else if (is_name (insn, "j") || is_name (insn, "jal")) {
		if (a[0].reg) {
			r_strbuf_appendf (sb, "%s,0,+", a[0].reg);
		} else {
			r_strbuf_appendf (sb, "0x%08"PFMT64x, op->jump);
		}
		if (is_name (insn, "jal")) {
			// Read the target before updating the link register (jal r15).
			r_strbuf_appendf (sb, ",0x%08"PFMT64x",r15,=", op->fail);
		}
		r_strbuf_append (sb, ",pc,=");
	} else if (is_name (insn, "rti")) {
		// Restoring status on interrupt return is not yet modeled.
		return;
	} else if (op->type == R_ANAL_OP_TYPE_LOAD || op->type == R_ANAL_OP_TYPE_STORE) {
		const unsigned base = d->format == 3? 1: 2;
		const unsigned delta = d->format == 3? 2: 1;
		if (op->type == R_ANAL_OP_TYPE_STORE) {
			r_strbuf_appendf (sb, "%s,", a[0].reg);
		}
		if (d->format == 3) {
			r_strbuf_append (sb, a[base].reg);
		} else {
			r_strbuf_appendf (sb, "0x%x,%s,+", (ut32)a[delta].value, a[base].reg);
		}
		if (op->type == R_ANAL_OP_TYPE_LOAD) {
			r_strbuf_appendf (sb, ",[%d],", op->refptr);
			if (op->sign) {
				r_strbuf_appendf (sb, "%d,SWAP,~,", op->refptr * 8);
			}
			r_strbuf_appendf (sb, "%s,=", a[0].reg);
		} else {
			r_strbuf_appendf (sb, ",=[%d]", op->refptr);
		}
		if (d->format == 3) {
			// When destination and base coincide, the hardware write ordering
			// has not been established. Do not invent an emulation result.
			if (op->type == R_ANAL_OP_TYPE_LOAD && !strcmp (a[0].reg, a[base].reg)) {
				r_strbuf_set (sb, "");
				return;
			}
			r_strbuf_appendf (sb, ",0x%x,%s,+,%s,=", (ut32)a[delta].value, a[base].reg, a[base].reg);
		}
	} else {
		const char *operator = NULL;
		if (is_name (insn, "add") || is_name (insn, "addsp")) {
			operator = "+";
		} else if (is_name (insn, "sub")) {
			operator = "-";
		} else if (is_name (insn, "and")) {
			operator = "&";
		} else if (is_name (insn, "or")) {
			operator = "|";
		} else if (is_name (insn, "xor")) {
			operator = "^";
		} else if (is_name (insn, "sll")) {
			operator = "<<";
		} else if (is_name (insn, "srl")) {
			operator = ">>";
		} else if (is_name (insn, "sra")) {
			operator = "ASR";
		} else if (is_name (insn, "mul")) {
			operator = "*";
		}
		if (operator) {
			const unsigned src = d->nargs == 2? 0: 1;
			const unsigned rhs = d->nargs == 2? 1: 2;
			esil_arg (sb, &a[rhs]);
			r_strbuf_append (sb, ",");
			esil_arg (sb, &a[src]);
			r_strbuf_appendf (sb, ",%s", operator);
			if (d->nargs == 4) {
				r_strbuf_appendf (sb, ",%d,+", a[3].value);
			}
			r_strbuf_appendf (sb, ",%s,=", a[0].reg);
		}
	}
}

static RArchValue operand_value(const Md32Operand *arg) {
	RArchValue v = { 0 };
	v.type = arg->reg? R_ANAL_VAL_REG: R_ANAL_VAL_IMM;
	v.reg = arg->reg;
	v.imm = arg->value;
	v.access = R_PERM_R;
	return v;
}

static void fill_values(RAnalOp *op, const Md32Insn *insn) {
	const Md32Opcode *d = insn->desc;
	const Md32Operand *a = insn->args;
	const bool load = op->type == R_ANAL_OP_TYPE_LOAD;
	const bool store = op->type == R_ANAL_OP_TYPE_STORE;
	if (load || store) {
		RArchValue mem = { 0 };
		mem.type = R_ANAL_VAL_MEM;
		mem.reg = op->ireg;
		mem.delta = op->disp;
		mem.memref = op->ptrsize;
		mem.access = load? R_PERM_R: R_PERM_W;
		RArchValue reg = operand_value (&a[0]);
		reg.access = load? R_PERM_W: R_PERM_R;
		RVecRArchValue_push_back (&op->srcs, load? &mem: &reg);
		RVecRArchValue_push_back (&op->dsts, load? &reg: &mem);
		if (d->format == 3) {
			RArchValue base = operand_value (&a[1]);
			RVecRArchValue_push_back (&op->srcs, &base);
			base.access = R_PERM_W;
			RVecRArchValue_push_back (&op->dsts, &base);
		}
		return;
	}
	if (is_flow (insn)) {
		unsigned i;
		for (i = 0; i < d->nargs; i++) {
			RArchValue v = operand_value (&a[i]);
			if (i + 1 == d->nargs && !a[i].reg) {
				v.imm = op->jump;
			}
			RVecRArchValue_push_back (&op->srcs, &v);
		}
		return;
	}
	if (op->type == R_ANAL_OP_TYPE_MOV || op->type == R_ANAL_OP_TYPE_ADD
		|| op->type == R_ANAL_OP_TYPE_SUB || op->type == R_ANAL_OP_TYPE_AND
		|| op->type == R_ANAL_OP_TYPE_OR || op->type == R_ANAL_OP_TYPE_XOR
		|| op->type == R_ANAL_OP_TYPE_SHL || op->type == R_ANAL_OP_TYPE_SHR
		|| op->type == R_ANAL_OP_TYPE_SAR || op->type == R_ANAL_OP_TYPE_ROL
		|| op->type == R_ANAL_OP_TYPE_ROR || is_name (insn, "mul")) {
		RArchValue dst = operand_value (&a[0]);
		dst.access = R_PERM_W;
		RVecRArchValue_push_back (&op->dsts, &dst);
		unsigned i;
		for (i = 1; i < d->nargs; i++) {
			RArchValue src = operand_value (&a[i]);
			if (is_name (insn, "sethi")) {
				src.imm = op->val;
			}
			RVecRArchValue_push_back (&op->srcs, &src);
		}
		if (d->nargs == 2 && op->type != R_ANAL_OP_TYPE_MOV) {
			dst.access = R_PERM_R;
			RVecRArchValue_push_back (&op->srcs, &dst);
		}
	}
}

static void fill_opex(RAnalOp *op, const Md32Insn *insn, unsigned count) {
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	if (count == 2) {
		pj_kb (pj, "parallel", true);
	}
	pj_ka (pj, "operands");
	unsigned slot, i;
	for (slot = 0; slot < count; slot++) {
		const Md32Insn *in = &insn[slot];
		for (i = 0; i < in->desc->nargs; i++) {
			const Md32Operand *a = &in->args[i];
			pj_o (pj);
			if (count == 2) {
				pj_ki (pj, "slot", slot);
			}
			pj_ks (pj, "type", a->reg? "reg": "imm");
			if (a->reg) {
				pj_ks (pj, "value", a->reg);
			} else {
				pj_kN (pj, "value", a->value);
			}
			pj_end (pj);
		}
	}
	pj_end (pj);
	pj_end (pj);
	r_strbuf_set (&op->opex, pj_string (pj));
	pj_free (pj);
}

static bool usip_decode(RAnalOp *op, RArchDecodeMask mask) {
	const ut16 h = r_read_be16 (op->bytes);
	const bool short_op = (h & 0x8000) != 0;
	const int available = op->size;
	op->size = short_op? 2: 4;
	if (available < op->size) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	RStrBuf sb;
	r_strbuf_init (&sb);
	op->type = R_ANAL_OP_TYPE_UNK;
	if (short_op) {
		if (h == 0xdef9) {
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			r_strbuf_set (&sb, "ret");
		} else if ((h & 0xff0f) == 0xff05) {
			r_strbuf_setf (&sb, "restore 0x%x", (h >> 4) & 15);
		} else if ((h & 0xff0f) == 0xdf05) {
			/* forma de 16 bits de `save` (doc 19 §11.2, 260 usos) */
			r_strbuf_setf (&sb, "save16 0x%x", (h >> 4) & 15);
		} else {
			r_strbuf_setf (&sb, ".hword 0x%04x", h);
		}
	} else {
		const ut16 lo = r_read_be16 (op->bytes + 2);
		if ((h == 0x000e && (lo & 0xf000) == 0x7000)
			|| (h == 0x400e && (lo & 0xf000) == 0xf000)) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = relative_target (op->addr, lo & 0xffe);
			op->fail = relative_target (op->addr, 4);
			r_strbuf_setf (&sb, "call 0x%08"PFMT64x, op->jump);
		} else if ((h == 0x000e && (lo & 0xf000) == 0x6000)
			|| (h == 0x400e && (lo & 0xf000) == 0xe000)) {
			// Vector stubs and independent function bodies agree on this
			// near relative jump. Do not extend the rule to other tags.
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = relative_target (op->addr, lo & 0xffe);
			op->eob = true;
			r_strbuf_setf (&sb, "j 0x%08"PFMT64x, op->jump);
			if (mask & R_ARCH_OP_MASK_ESIL) {
				r_strbuf_setf (&op->esil, "0x%08"PFMT64x",pc,=", op->jump);
			}
		} else if ((h & 0xff0f) == 0x5f05) {
			r_strbuf_setf (&sb, "save 0x%04x, 0x%x", lo, (h >> 4) & 15);
		} else if (h == 0x5ef9) {
			/* ret en forma de 32 bits (doc 19 §11.2, 121 usos) */
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			r_strbuf_set (&sb, "ret");
		} else if ((h & 0xff0f) == 0x7f05) {
			/* restore en forma de 32 bits (93 usos) */
			r_strbuf_setf (&sb, "restore 0x%x", (h >> 4) & 15);
		} else if ((h & 0xf1ff) == 0x400c
			&& (lo & 0xf000) >= 0xc000 && (lo & 0xf000) <= 0xe000) {
			/* Corpus-derived numeric condition and target, still provisional.
			 * The supplied rule covers C/D/E only, not every tag >= C. */
			const unsigned cond = (h >> 9) & 7;
			op->cond = R_ANAL_CONDTYPE_ERR;
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = relative_target (op->addr, lo & 0xffe);
			op->fail = relative_target (op->addr, 4);
			r_strbuf_setf (&sb, "b%u 0x%08"PFMT64x, cond, op->jump);
		} else {
			r_strbuf_setf (&sb, ".word 0x%04x%04x", h, lo);
		}
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain_nofree (&sb);
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		PJ *pj = pj_new ();
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "encoding", "usip");
			pj_ki (pj, "width", op->size * 8);
			pj_ki (pj, "hw1", h);
			pj_ki (pj, "opcode_without_width_bit", h & 0x7fff);
			pj_kb (pj, "provisional", true);
			if (!short_op) {
				const ut16 extension = r_read_be16 (op->bytes + 2);
				pj_ki (pj, "extension", extension);
				pj_ki (pj, "tag", extension >> 12);
				if (h == 0x5ef9) {
					pj_kb (pj, "extension_semantics_unresolved", true);
				}
			}
			if (op->type == R_ANAL_OP_TYPE_CJMP) {
				pj_ki (pj, "condition_index", (h >> 9) & 7);
			}
			pj_end (pj);
			r_strbuf_set (&op->opex, pj_string (pj));
			pj_free (pj);
		}
	}
	r_strbuf_fini (&sb);
	return true;
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	const int available = op->size;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->size = 2;
	op->jump = op->fail = op->ptr = op->val = UT64_MAX;
	op->delay = 0;
	op->eob = false;
	if (available < 2 || !op->bytes) {
		return false;
	}
	if (s->config->cpu && !strcmp (s->config->cpu, "usip")) {
		op->size = available;
		return usip_decode (op, mask);
	}
	const ut16 h = r_read_be16 (op->bytes);
	const unsigned top = h >> 13;
	Md32Insn insn[2] = { 0 };
	unsigned count = 1;
	bool valid;
	if (top == 0 || top == 1) {
		op->size = 4;
		valid = available >= 4 && decode_insn (&insn[0], r_read_be32 (op->bytes), 1);
	} else if (top == 2 || top == 3) {
		// A packed pair has a shared format prefix. Bit 15 of the second
		// halfword is the low bit of the first decoded instruction.
		op->size = 4;
		valid = false;
		if (available >= 4) {
			const ut16 lo = r_read_be16 (op->bytes + 2);
			const unsigned suffix = lo & 0x6000;
			if (suffix == 0x2000 || suffix == 0x6000) {
				valid = decode_insn (&insn[0], (ut16)((h << 1) | (lo >> 15)), top == 2? 4: 5)
					&& decode_insn (&insn[1], lo | 0x8000, suffix == 0x2000? 6: 7);
				count = 2;
			}
		}
	} else {
		const unsigned group[] = { 4, 6, 5, 7 };
		valid = decode_insn (&insn[0], h, group[top - 4]);
	}
	if (!valid) {
		op->size = 2;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	// Packed branches execute after the other slot. Keep their flow metadata.
	const Md32Insn *flow = count == 2 && is_flow (&insn[1])? &insn[1]: &insn[0];
	analyze_insn (op, flow);
	op->id = (ut32)(flow->desc - md32_opcodes) + 1;
	if (op->delay && op->fail != UT64_MAX) {
		// Delay is measured in decoded instructions/bundles, not bytes.
		// Only report the fallthrough when all delay lengths are available.
		int offset = op->size;
		int n;
		for (n = 0; n < op->delay; n++) {
			if (offset + 2 > available) {
				break;
			}
			const ut16 next = r_read_be16 (op->bytes + offset);
			const int size = (next & 0x8000)? 2: 4;
			if (offset + size > available) {
				break;
			}
			offset += size;
		}
		op->fail = n == op->delay? relative_target (op->addr, offset): UT64_MAX;
	}
	if (count == 2 && !is_flow (flow)) {
		// Two operations cannot be represented by a single scalar op type.
		op->type = R_ANAL_OP_TYPE_UNK;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		RStrBuf sb;
		r_strbuf_init (&sb);
		format_insn (&sb, &insn[0], op->addr);
		if (count == 2) {
			r_strbuf_append (&sb, " | ");
			format_insn (&sb, &insn[1], op->addr);
		}
		op->mnemonic = r_strbuf_drain_nofree (&sb);
		r_strbuf_fini (&sb);
	}
	if ((mask & R_ARCH_OP_MASK_VAL) && count == 1) {
		fill_values (op, &insn[0]);
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		fill_opex (op, insn, count);
	}
	if ((mask & R_ARCH_OP_MASK_ESIL) && count == 1) {
		insn_esil (op, &insn[0]);
	}
	return true;
}

static int info(RArchSession *s, ut32 query) {
	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_FUNC_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 4;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

static char *regs(RArchSession *s) {
	// The uSIP ABI is not established by the supplied material.
	if (s->config->cpu && !strcmp (s->config->cpu, "usip")) {
		return strdup ("=PC pc\ngpr pc .32 0 0\n");
	}
	return strdup (
		"=PC pc\n=SP r14\n=LR r15\n=A0 r3\n=A1 r4\n=A2 r5\n=A3 r6\n=A4 r7\n=A5 r8\n=A6 r9\n=A7 r10\n=R0 r1\n=R1 r2\n"
		"gpr r0 .32 0 0\ngpr r1 .32 4 0\ngpr r2 .32 8 0\ngpr r3 .32 12 0\n"
		"gpr r4 .32 16 0\ngpr r5 .32 20 0\ngpr r6 .32 24 0\ngpr r7 .32 28 0\n"
		"gpr r8 .32 32 0\ngpr r9 .32 36 0\ngpr r10 .32 40 0\ngpr r11 .32 44 0\n"
		"gpr r12 .32 48 0\ngpr r13 .32 52 0\ngpr r14 .32 56 0\ngpr r15 .32 60 0\n"
		"gpr pc .32 64 0\ngpr sr .32 68 0\ngpr ipc .32 72 0\ngpr isr .32 76 0\n"
		"gpr lf .32 80 0\ngpr ls0 .32 84 0\ngpr le0 .32 88 0\ngpr lc0 .32 92 0\n"
		"gpr ls1 .32 96 0\ngpr le1 .32 100 0\ngpr lc1 .32 104 0\n"
		"gpr ls2 .32 108 0\ngpr le2 .32 112 0\ngpr lc2 .32 116 0\n"
		"gpr dbg .32 120 0\ngpr a0 .64 128 0\ngpr a0l .32 128 0\ngpr a0h .32 132 0\n");
}

RArchPlugin r_arch_plugin_md32 = {
	.meta = {
		.name = "md32",
		.desc = "MediaTek MD32 (MS15E30) and experimental uSIP",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "md32",
	.cpus = "md32,ms15e30,usip",
	.bits = R_SYS_BITS_PACK1 (32),
	.addr_bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_BIG,
	.decode = decode,
	.info = info,
	.regs = regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_md32,
	.version = R2_VERSION
};
#endif
