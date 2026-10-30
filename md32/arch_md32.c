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
#define USIP_OPCODES_NO_TABLE
#include "usip_opcodes.h"
#include "usip_decode.h"

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
	if (is_name (insn, "rem")) {
		return R_ANAL_OP_TYPE_MOD;
	}
	if (is_name (insn, "cmulcr") || is_name (insn, "cmulci") || is_name (insn, "cmulr") || is_name (insn, "cmuli")) {
		return R_ANAL_OP_TYPE_MUL;
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
	} else if (is_name (insn, "rem")) {
		// rem16 rn, rm: rn = rn mod rm. Every observed use is a non-negative modulo-N wrap; the sign
		// convention for negative dividends is not established, unsigned is assumed here.
		r_strbuf_setf (sb, "%s,%s,%%,%s,=", a[1].reg, a[0].reg, a[0].reg);
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

/* ------------------------------------------------------------------------------------------------ uSIP (VLIW packets) */
/* The uSIP instruction stream is a VLIW packet stream of 16-bit units whose instructions may interleave
 * (see usip_decode.h).  A decode at the first unit of a packet parses the whole packet and caches it in the session,
 * so that the following decodes inside the same packet (linear disassembly and analysis) see the same reading:
 * every head is emitted as an instruction whose size covers its own adjacent units, and a unit that is the tail of
 * an instruction whose head lies elsewhere in the packet is emitted as `.unit` naming its instruction.  A decode at
 * an address that is not cached is treated as a packet start (branch targets and function starts always are). */

#define USIP_CACHE_SIZE 64

typedef struct {
	UsipPacket pk[USIP_CACHE_SIZE];
	int next;
} UsipState;

static bool md32_init(RArchSession *s) {
	if (s) {
		s->data = R_NEW0 (UsipState);
	}
	return true;
}

static bool md32_fini(RArchSession *s) {
	/* r_arch_plugin_remove calls fini (NULL) when the plugin is unloaded */
	if (s) {
		R_FREE (s->data);
	}
	return true;
}

static bool usip_cpu(RArchSession *s) {
	return s && s->config && s->config->cpu && !strcmp (s->config->cpu, "usip");
}

/* the cached packet containing addr whose units still match the bytes at hand */
static UsipPacket *usip_cached_packet(UsipState *st, ut64 addr, const ut8 *bytes, int len) {
	int i;
	if (!st) {
		return NULL;
	}
	for (i = 0; i < USIP_CACHE_SIZE; i++) {
		UsipPacket *pk = &st->pk[i];
		if (!pk->nunits || addr < pk->addr || addr >= pk->addr + 2 * (ut64)pk->nunits) {
			continue;
		}
		const int u0 = (int)((addr - pk->addr) / 2);
		int u;
		bool same = true;
		for (u = u0; u < pk->nunits && 2 * (u - u0 + 1) <= len; u++) {
			if (r_read_be16 (bytes + 2 * (u - u0)) != pk->units[u]) {
				same = false;
				break;
			}
		}
		if (!same) {
			pk->nunits = 0;
			continue;
		}
		if (pk->truncated && len > 2 * (pk->nunits - u0)) {
			/* more of the packet is visible now: complete the units from the cache and re-decode */
			ut16 units[USIP_MAX_UNITS];
			bool truncated;
			int n = u0;
			memcpy (units, pk->units, u0 * sizeof (ut16));
			n += usip_scan_units (bytes, R_MIN (len, 2 * (USIP_MAX_UNITS - u0)), units + u0, &truncated);
			usip_decode_packet (pk, pk->addr, units, n, truncated);
		}
		return pk;
	}
	return NULL;
}

static bool usip_name_is(const char *mn, const char *name) {
	const size_t len = strlen (name);
	return !strncmp (mn, name, len) && (!mn[len] || mn[len] == '.');
}

static int usip_alu_type(const char *mn) {
	static const struct { const char *name; int type; } table[] = {
		{ "add", R_ANAL_OP_TYPE_ADD }, { "addi", R_ANAL_OP_TYPE_ADD }, { "inc", R_ANAL_OP_TYPE_ADD }, { "lea", R_ANAL_OP_TYPE_LEA },
		{ "L_add", R_ANAL_OP_TYPE_ADD }, { "sub", R_ANAL_OP_TYPE_SUB }, { "dec", R_ANAL_OP_TYPE_SUB }, { "rsub", R_ANAL_OP_TYPE_SUB },
		{ "neg", R_ANAL_OP_TYPE_SUB }, { "L_sub", R_ANAL_OP_TYPE_SUB }, { "and", R_ANAL_OP_TYPE_AND }, { "band", R_ANAL_OP_TYPE_AND },
		{ "bclr", R_ANAL_OP_TYPE_AND }, { "or", R_ANAL_OP_TYPE_OR }, { "bset", R_ANAL_OP_TYPE_OR }, { "xor", R_ANAL_OP_TYPE_XOR },
		{ "binv", R_ANAL_OP_TYPE_XOR }, { "lsl", R_ANAL_OP_TYPE_SHL }, { "shl", R_ANAL_OP_TYPE_SHL }, { "L_shl", R_ANAL_OP_TYPE_SHL },
		{ "lsr", R_ANAL_OP_TYPE_SHR }, { "shr", R_ANAL_OP_TYPE_SHR }, { "L_shr", R_ANAL_OP_TYPE_SHR }, { "bext", R_ANAL_OP_TYPE_SHR },
		{ "asr", R_ANAL_OP_TYPE_SAR }, { "asr16", R_ANAL_OP_TYPE_SAR }, { "mov", R_ANAL_OP_TYPE_MOV }, { "cmov", R_ANAL_OP_TYPE_CMOV },
		{ "seq", R_ANAL_OP_TYPE_CMP }, { "slt", R_ANAL_OP_TYPE_CMP }, { "sltu", R_ANAL_OP_TYPE_CMP }, { "sgt", R_ANAL_OP_TYPE_CMP },
		{ "sext", R_ANAL_OP_TYPE_CAST }, { "zext", R_ANAL_OP_TYPE_CAST }, { "sext16", R_ANAL_OP_TYPE_CAST }, { "zext16", R_ANAL_OP_TYPE_CAST },
		{ "mul", R_ANAL_OP_TYPE_MUL }, { "mul16", R_ANAL_OP_TYPE_MUL }, { "mulu16", R_ANAL_OP_TYPE_MUL }, { "mult", R_ANAL_OP_TYPE_MUL },
		{ "mac", R_ANAL_OP_TYPE_MUL }, { "L_mult", R_ANAL_OP_TYPE_MUL }, { "L_mac", R_ANAL_OP_TYPE_MUL }, { "Mpy_32_16", R_ANAL_OP_TYPE_MUL },
		{ "Mpy_32_32", R_ANAL_OP_TYPE_MUL }, { "mul3216", R_ANAL_OP_TYPE_MUL }, { "muls64", R_ANAL_OP_TYPE_MUL }, { "mulu64", R_ANAL_OP_TYPE_MUL },
		{ "divs", R_ANAL_OP_TYPE_DIV }, { "divu", R_ANAL_OP_TYPE_DIV }, { "abs_s", R_ANAL_OP_TYPE_ABS }, { "L_abs", R_ANAL_OP_TYPE_ABS },
		{ "mfacc", R_ANAL_OP_TYPE_MOV },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (table); i++) {
		if (usip_name_is (mn, table[i].name)) {
			return table[i].type;
		}
	}
	return R_ANAL_OP_TYPE_UNK;
}

static int usip_optype(const UsipInsn *in) {
	const char *mn = in->mnem;
	switch (in->kind) {
	case USIP_K_BR:
		return !strcmp (mn, "b")? R_ANAL_OP_TYPE_JMP: R_ANAL_OP_TYPE_CJMP;
	case USIP_K_BR16:
	case USIP_K_BR16D:
		return !strcmp (mn, "b.s")? R_ANAL_OP_TYPE_JMP: R_ANAL_OP_TYPE_CJMP;
	case USIP_K_CALL:
	case USIP_K_CALL16:
	case USIP_K_CALLA:
		return R_ANAL_OP_TYPE_CALL;
	case USIP_K_CALLR:
		return R_ANAL_OP_TYPE_RCALL;
	case USIP_K_JUMPA:
		return R_ANAL_OP_TYPE_JMP;
	case USIP_K_RET:
		return R_ANAL_OP_TYPE_RET;
	case USIP_K_NOP:
		return R_ANAL_OP_TYPE_NOP;
	case USIP_K_SYS:
		return R_ANAL_OP_TYPE_SWI;
	case USIP_K_SAVE:
		return R_ANAL_OP_TYPE_RPUSH;
	case USIP_K_RESTORE:
		return R_ANAL_OP_TYPE_POP;
	case USIP_K_LD:
		return usip_name_is (mn, "lea")? R_ANAL_OP_TYPE_LEA: R_ANAL_OP_TYPE_LOAD;
	case USIP_K_ST:
		return R_ANAL_OP_TYPE_STORE;
	case USIP_K_MEM16:
		return mn[0] == 'l'? R_ANAL_OP_TYPE_LOAD: R_ANAL_OP_TYPE_STORE;
	case USIP_K_MOV:
	case USIP_K_MOV32:
	case USIP_K_MOVI:
	case USIP_K_MOVI21:
	case USIP_K_MOVI32:
	case USIP_K_CSR:
		return R_ANAL_OP_TYPE_MOV;
	case USIP_K_ALU:
	case USIP_K_ALU32:
	case USIP_K_BIT:
	case USIP_K_MUL:
	case USIP_K_DSP:
	case USIP_K_DSPACC:
		return usip_alu_type (mn);
	}
	return R_ANAL_OP_TYPE_UNK;
}

static void usip_branch_cond(RAnalOp *op, const char *mn) {
	static const struct { const char *name; int cond; bool sign; } table[] = {
		{ "beq", R_ANAL_CONDTYPE_EQ, false }, { "bne", R_ANAL_CONDTYPE_NE, false }, { "blt", R_ANAL_CONDTYPE_LT, true },
		{ "ble", R_ANAL_CONDTYPE_LE, true }, { "bgt", R_ANAL_CONDTYPE_GT, true }, { "bge", R_ANAL_CONDTYPE_GE, true },
		{ "bltu", R_ANAL_CONDTYPE_LO, false }, { "bleu", R_ANAL_CONDTYPE_LS, false }, { "bgtu", R_ANAL_CONDTYPE_HI, false },
		{ "bgeu", R_ANAL_CONDTYPE_HS, false }, { "beqz", R_ANAL_CONDTYPE_EQ, false }, { "bnez", R_ANAL_CONDTYPE_NE, false },
		{ "bz", R_ANAL_CONDTYPE_EQ, false }, { "bnz", R_ANAL_CONDTYPE_NE, false },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (table); i++) {
		if (usip_name_is (mn, table[i].name)) {
			op->cond = table[i].cond;
			op->sign = table[i].sign;
			return;
		}
	}
}

/* decoded field value by name (the format fields come first in op->fields) */
static bool usip_field(const UsipInsn *in, const char *name, st64 *value) {
	int i;
	for (i = 0; i < in->nvals; i++) {
		const char *nm = usip_op_field_name (in->op, i);
		if (nm && !strcmp (nm, name)) {
			*value = in->vals[i];
			return true;
		}
	}
	return false;
}

static int usip_nruns(const UsipPacket *pk) {
	int u, runs = 0;
	for (u = 0; u < pk->nunits; u++) {
		if (!u || pk->owner[u] != pk->owner[u - 1]) {
			runs++;
		}
	}
	return runs;
}

static void usip_analyze(RAnalOp *op, const UsipPacket *pk, int k) {
	const UsipInsn *in = &pk->insn[k];
	const ut64 pkt_end = pk->addr + 2 * (ut64)pk->nunits;
	st64 v;
	op->type = usip_optype (in);
	switch (in->kind) {
	case USIP_K_BR:
	case USIP_K_BR16:
	case USIP_K_BR16D:
		if (in->has_target) {
			op->jump = in->target;
		}
		if (op->type == R_ANAL_OP_TYPE_CJMP) {
			op->fail = pkt_end;
			usip_branch_cond (op, in->mnem);
		} else {
			op->eob = true;
		}
		break;
	case USIP_K_CALL:
	case USIP_K_CALL16:
	case USIP_K_CALLA:
		if (in->has_target) {
			op->jump = in->target;
		}
		op->fail = pkt_end;
		break;
	case USIP_K_CALLR:
		if (usip_field (in, "rB", &v)) {
			op->reg = gpregs[v & 15];
		}
		op->fail = pkt_end;
		break;
	case USIP_K_JUMPA:
		if (in->has_target) {
			op->jump = in->target;
		}
		op->eob = true;
		break;
	case USIP_K_RET:
		op->eob = true;
		op->reg = "r15";
		break;
	case USIP_K_LOOP:
		/* The loop setup does not branch: the back edge is at the (inclusive) loop end. */
		if (in->has_target) {
			op->ptr = in->target;
			op->direction = R_ANAL_OP_DIR_REF;
		}
		if (usip_field (in, "rX", &v)) {
			op->reg = gpregs[v & 15];
		}
		break;
	case USIP_K_LD:
	case USIP_K_ST:
	case USIP_K_MEM16:
		if (op->type == R_ANAL_OP_TYPE_LOAD || op->type == R_ANAL_OP_TYPE_STORE) {
			const char *mn = in->mnem;
			const char *dot = strchr (mn, '.');
			const char w = dot? dot[1]: 'w';
			op->refptr = w == 'w'? 4: w == 'h'? 2: w == 'b'? 1: 0;
			op->ptrsize = op->refptr;
			op->sign = dot && (dot[2] == 0 || dot[2] == '?') && (w == 'h' || w == 'b');
			op->direction = op->type == R_ANAL_OP_TYPE_LOAD? R_ANAL_OP_DIR_READ: R_ANAL_OP_DIR_WRITE;
			if (usip_field (in, "rA", &v)) {
				op->ireg = gpregs[v & 15];
				if ((v & 15) == 14) {
					op->stackop = op->type == R_ANAL_OP_TYPE_LOAD? R_ANAL_STACK_GET: R_ANAL_STACK_SET;
				}
			} else if (usip_name_is (mn, "ld.sp") || usip_name_is (mn, "st.sp")) {
				op->ireg = "r14";
				op->stackop = op->type == R_ANAL_OP_TYPE_LOAD? R_ANAL_STACK_GET: R_ANAL_STACK_SET;
			}
			if (usip_field (in, "off", &v) || usip_field (in, "off12", &v) || usip_field (in, "off11", &v) || usip_field (in, "imm", &v)) {
				op->disp = (ut64)v;
			}
			if (usip_field (in, "addr", &v) || usip_field (in, "imm27", &v)) {
				op->ptr = v;
			}
		}
		break;
	default:
		break;
	}
	if (op->type == R_ANAL_OP_TYPE_MOV || in->kind == USIP_K_MOV32) {
		if (usip_field (in, "V", &v) || usip_field (in, "val", &v) || usip_field (in, "imm", &v) || usip_field (in, "addr", &v)) {
			op->val = (ut64)v;
		}
	}
	if (k == pk->owner[0] && pk->delay) {
		/* the rest of the packet executes before the transfer: one op per run of units */
		op->delay = usip_nruns (pk) - 1;
	}
}

static void usip_opex(RAnalOp *op, const UsipPacket *pk, int k, int unit) {
	const UsipInsn *in = &pk->insn[k];
	PJ *pj = pj_new ();
	int i;
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ks (pj, "encoding", "usip");
	if (in->head != unit) {
		pj_kb (pj, "tail", true);
		pj_kn (pj, "insn_addr", usip_unit_addr (pk, in->head));
	}
	pj_ks (pj, "mnemonic", in->mnem);
	if (in->op) {
		pj_ks (pj, "form", usip_op_form (in->op));
		pj_ks (pj, "confidence", usip_conf_name (usip_op_conf (in->op)));
	}
	pj_ks (pj, "kind", usip_kind_name (in->kind));
	pj_ki (pj, "slot", k);
	pj_ka (pj, "units");
	pj_n (pj, usip_unit_addr (pk, in->head));
	for (i = 0; i < in->ntails; i++) {
		pj_n (pj, usip_unit_addr (pk, in->tails[i]));
	}
	pj_end (pj);
	pj_kb (pj, "delay_slot", pk->delay && k != pk->owner[0]);
	pj_ko (pj, "packet");
	pj_kn (pj, "addr", pk->addr);
	pj_ki (pj, "units", pk->nunits);
	pj_ki (pj, "insns", pk->ninsn);
	pj_kb (pj, "ambiguous", pk->ambiguous);
	pj_kb (pj, "truncated", pk->truncated);
	pj_kb (pj, "delay", pk->delay);
	pj_end (pj);
	if (in->op) {
		pj_ka (pj, "operands");
		for (i = 0; i < usip_op_nargs (in->op) && i < in->nvals; i++) {
			const int t = usip_op_field_type (in->op, i);
			pj_o (pj);
			pj_ks (pj, "name", usip_op_field_name (in->op, i));
			if (t == USIP_A_REG) {
				pj_ks (pj, "type", "reg");
				pj_ks (pj, "value", gpregs[in->vals[i] & 15]);
			} else if (t == USIP_A_FLAG) {
				pj_ks (pj, "type", "flag");
				pj_kN (pj, "value", in->vals[i]);
			} else if (t == USIP_A_DISP || t == USIP_A_UDISP || t == USIP_A_ABSADDR) {
				pj_ks (pj, "type", "addr");
				pj_kn (pj, "value", t == USIP_A_ABSADDR? (ut64)in->vals[i]: (usip_unit_addr (pk, in->head) + (ut64)in->vals[i]) & UT32_MAX);
			} else {
				pj_ks (pj, "type", "imm");
				pj_kN (pj, "value", in->vals[i]);
			}
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
	r_strbuf_set (&op->opex, pj_string (pj));
	pj_free (pj);
}

static bool usip_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	const int available = op->size;
	UsipState *st = s? (UsipState *)s->data: NULL;
	UsipPacket local;
	UsipPacket *pk = usip_cached_packet (st, op->addr, op->bytes, available);
	if (!pk) {
		ut16 units[USIP_MAX_UNITS];
		bool truncated;
		const int n = usip_scan_units (op->bytes, available, units, &truncated);
		if (n < 1) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->size = 2;
			return false;
		}
		if (st) {
			pk = &st->pk[st->next];
			st->next = (st->next + 1) % USIP_CACHE_SIZE;
		} else {
			pk = &local;
		}
		usip_decode_packet (pk, op->addr, units, n, truncated);
	}
	const int unit = (int)((op->addr - pk->addr) / 2);
	const int k = pk->owner[unit];
	const UsipInsn *in = &pk->insn[k];
	int run = 1;
	while (unit + run < pk->nunits && pk->owner[unit + run] == k) {
		run++;
	}
	op->size = 2 * run;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->id = in->op? usip_op_index (in->op) + 1: 0;
	if (in->head == unit) {
		usip_analyze (op, pk, k);
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		RStrBuf sb;
		r_strbuf_init (&sb);
		if (in->head == unit) {
			usip_insn_text (pk, k, &sb);
		} else {
			int i;
			r_strbuf_append (&sb, ".unit 0x");
			for (i = 0; i < run; i++) {
				r_strbuf_appendf (&sb, "%04x", pk->units[unit + i]);
			}
			r_strbuf_appendf (&sb, " (%s @ 0x%08"PFMT64x")", in->mnem, usip_unit_addr (pk, in->head));
		}
		op->mnemonic = r_strbuf_drain_nofree (&sb);
		r_strbuf_fini (&sb);
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		usip_opex (op, pk, k, unit);
	}
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
	if (usip_cpu (s)) {
		op->size = available;
		return usip_decode (s, op, mask);
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
		/* A uSIP decode needs the whole packet (up to 8 units) even though one op covers at most 3 of them. */
		return usip_cpu (s)? 2 * USIP_MAX_UNITS: 4;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

static char *regs(RArchSession *s) {
	if (usip_cpu (s)) {
		// uSIP ABI (reverse-engineered): r14 = SP, r15 = LR, arguments r0-r7, return r0 (r0:r1), callee-saved
		// r8-r10, r12, r13 (save/restore sets); the second register bank (rN!) and the 72-bit accumulators are
		// exposed as plain 32-bit words.
		return strdup (
			"=PC pc\n=SP r14\n=LR r15\n=A0 r0\n=A1 r1\n=A2 r2\n=A3 r3\n=A4 r4\n=A5 r5\n=A6 r6\n=A7 r7\n=R0 r0\n=R1 r1\n"
			"gpr r0 .32 0 0\ngpr r1 .32 4 0\ngpr r2 .32 8 0\ngpr r3 .32 12 0\n"
			"gpr r4 .32 16 0\ngpr r5 .32 20 0\ngpr r6 .32 24 0\ngpr r7 .32 28 0\n"
			"gpr r8 .32 32 0\ngpr r9 .32 36 0\ngpr r10 .32 40 0\ngpr r11 .32 44 0\n"
			"gpr r12 .32 48 0\ngpr r13 .32 52 0\ngpr r14 .32 56 0\ngpr r15 .32 60 0\n"
			"gpr pc .32 64 0\ngpr sr .32 68 0\ngpr ipc .32 72 0\ngpr isr .32 76 0\n"
			"gpr lf .32 80 0\ngpr ls0 .32 84 0\ngpr le0 .32 88 0\ngpr lc0 .32 92 0\n"
			"gpr ls1 .32 96 0\ngpr le1 .32 100 0\ngpr lc1 .32 104 0\n"
			"gpr ls2 .32 108 0\ngpr le2 .32 112 0\ngpr lc2 .32 116 0\n"
			"gpr r8h .32 120 0\ngpr r9h .32 124 0\ngpr r10h .32 128 0\ngpr r11h .32 132 0\n"
			"gpr r12h .32 136 0\ngpr r13h .32 140 0\ngpr r14h .32 144 0\ngpr r15h .32 148 0\n"
			"gpr a0lo .32 152 0\ngpr a0hi .32 156 0\ngpr a0ext .32 160 0\n"
			"gpr a1lo .32 164 0\ngpr a1hi .32 168 0\ngpr a1ext .32 172 0\n"
			"gpr a2lo .32 176 0\ngpr a2hi .32 180 0\ngpr a2ext .32 184 0\n"
			"gpr a3lo .32 188 0\ngpr a3hi .32 192 0\ngpr a3ext .32 196 0\n");
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
		.desc = "MediaTek MD32 (MS15E30) and uSIP (VLIW packets)",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "md32",
	.cpus = "md32,ms15e30,usip",
	.bits = R_SYS_BITS_PACK1 (32),
	.addr_bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_BIG,
	.init = md32_init,
	.fini = md32_fini,
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
