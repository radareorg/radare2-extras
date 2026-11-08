/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* Panasonic (Matsushita) MN10300 / AM33 architecture plugin: table-driven decoder (the GNU binutils
 * opcode table), analysis metadata, ESIL for the integer core and a register profile. */

#include <r_arch.h>
#include "mn103_decode.h"
#include "mn103_decode.c"

/* ------------------------------------------------------------------------------------------------ logical operands */

typedef enum {
	ARG_NONE = 0,
	ARG_REG,
	ARG_IMM,
	ARG_MEM,
	ARG_PCREL,
	ARG_REGLIST,
} Mn103ArgKind;

typedef struct {
	Mn103ArgKind kind;
	const char *reg;     /* ARG_REG */
	st32 imm;            /* ARG_IMM value, ARG_PCREL target, ARG_REGLIST mask */
	ut32 flags;          /* operand flags of the immediate */
	const char *base;    /* ARG_MEM base register, NULL for an absolute address */
	const char *index;   /* ARG_MEM index register */
	st32 disp;           /* ARG_MEM displacement or absolute address */
	bool abs;            /* ARG_MEM absolute address */
	bool postinc;        /* ARG_MEM post-increment (an+) or (an+, imm) */
	st32 inc;            /* post-increment amount, 0 = the access size */
} Mn103Arg;

#define MN103_MAX_ARGS 4

typedef struct {
	Mn103Insn in;
	int nargs;
	Mn103Arg args[MN103_MAX_ARGS];
	int access;          /* memory access size in bytes */
	ut64 next;           /* address of the next instruction */
} Mn103Op;

static bool name_starts(const Mn103Op *o, const char *prefix) {
	return o->in.desc && !strncmp (o->in.desc->name, prefix, strlen (prefix));
}

static int access_size(const Mn103Op *o) {
	const char *n = o->in.desc->name;
	if (!strcmp (n, "movbu")) {
		return 1;
	}
	if (!strcmp (n, "movhu")) {
		return 2;
	}
	if (!strcmp (n, "bset") || !strcmp (n, "bclr") || !strcmp (n, "btst")) {
		return 1;
	}
	if (!strcmp (n, "fmov")) {
		int i;
		for (i = 0; i < o->in.nops; i++) {
			if (o->in.ops[i].flags & MN103_OPERAND_FDREG) {
				return 8;
			}
		}
	}
	return 4;
}

static void build_args(Mn103Op *o) {
	const Mn103Insn *in = &o->in;
	int i;
	bool paren = false;
	Mn103Arg *mem = NULL;
	o->nargs = 0;
	o->access = access_size (o);
	for (i = 0; i < in->nops; i++) {
		const Mn103Operand *p = &in->ops[i];
		const ut32 fl = p->flags;
		if (p->index == MN103_OP_UNUSED) {
			continue;
		}
		if (fl & MN103_OPERAND_PAREN) {
			if (!paren) {
				if (o->nargs >= MN103_MAX_ARGS) {
					break;
				}
				mem = &o->args[o->nargs++];
				memset (mem, 0, sizeof (*mem));
				mem->kind = ARG_MEM;
			}
			paren = !paren;
			continue;
		}
		if (paren && mem) {
			if (fl & MN103_OPERAND_PLUS) {
				mem->postinc = true;
			} else if (p->reg) {
				if (mem->base) {
					mem->index = mem->base;
				}
				mem->base = p->reg;
			} else if (mem->postinc) {
				mem->inc = p->value;
			} else {
				mem->disp = p->value;
				mem->abs = !!(fl & MN103_OPERAND_MEMADDR);
			}
			continue;
		}
		if (o->nargs >= MN103_MAX_ARGS) {
			break;
		}
		Mn103Arg *a = &o->args[o->nargs++];
		memset (a, 0, sizeof (*a));
		a->flags = fl;
		if (p->reg) {
			a->kind = ARG_REG;
			a->reg = p->reg;
		} else if (fl & MN103_OPERAND_PCREL) {
			a->kind = ARG_PCREL;
			a->imm = p->value;
		} else if (fl & MN103_OPERAND_REG_LIST) {
			a->kind = ARG_REGLIST;
			a->imm = p->value;
		} else {
			a->kind = ARG_IMM;
			a->imm = p->value;
		}
	}
	/* a memory operand with a PCREL/MEMADDR immediate inside and no register is absolute */
	for (i = 0; i < o->nargs; i++) {
		if (o->args[i].kind == ARG_MEM && !o->args[i].base) {
			o->args[i].abs = true;
		}
	}
}

/* ------------------------------------------------------------------------------------------------ register lists */

typedef struct {
	const char *name;
	bool dummy;
} Mn103Slot;

/* Push order of movm [...],(sp): the first entry ends at the highest address. The d2/d3/a2/a3 group lies at the
 * lowest addresses and the extended groups above it (the pt_regs layout of the Linux MN10300 port); the `other`
 * group is placed above all of them (Linux pushes it with a separate movm, so its relative order is not observable
 * there). Within `other` the dummy word (the USP slot) is the lowest. */
static int reglist_slots(ut32 mask, Mn103Slot *slots, int max) {
	int n = 0;
#define SLOT(nm, dm) do { if (n < max) { slots[n].name = nm; slots[n].dummy = dm; n++; } } while (0)
	if (mask & MN103_REGS_OTHER) {
		SLOT ("d0", false); SLOT ("d1", false); SLOT ("a0", false); SLOT ("a1", false);
		SLOT ("mdr", false); SLOT ("lir", false); SLOT ("lar", false); SLOT (NULL, true);
	}
	if (mask & MN103_REGS_EXREG1) {
		SLOT ("r2", false); SLOT ("r3", false); SLOT ("r4", false); SLOT ("r5", false); SLOT ("r6", false); SLOT ("r7", false);
	}
	if (mask & MN103_REGS_EXREG0) {
		SLOT ("r0", false); SLOT ("r1", false);
	}
	if (mask & MN103_REGS_EXOTHER) {
		SLOT ("mdrq", false); SLOT ("mcrh", false); SLOT ("mcrl", false); SLOT ("mcvf", false);
	}
	if (mask & MN103_REGS_D2) {
		SLOT ("d2", false);
	}
	if (mask & MN103_REGS_D3) {
		SLOT ("d3", false);
	}
	if (mask & MN103_REGS_A2) {
		SLOT ("a2", false);
	}
	if (mask & MN103_REGS_A3) {
		SLOT ("a3", false);
	}
#undef SLOT
	return n;
}

static int reglist_bytes(ut32 mask) {
	Mn103Slot slots[32];
	return 4 * reglist_slots (mask, slots, 32);
}

/* ------------------------------------------------------------------------------------------------ analysis */

typedef struct {
	const char *name;
	int cond;
	bool sign;
	const char *esil;    /* condition expression leaving 1/0 on the stack */
} Mn103Cond;

static const Mn103Cond mn103_conds[] = {
	{ "eq", R_ANAL_CONDTYPE_EQ, false, "zf" },
	{ "ne", R_ANAL_CONDTYPE_NE, false, "zf,!" },
	{ "gt", R_ANAL_CONDTYPE_GT, true, "zf,nf,vf,^,|,!" },
	{ "ge", R_ANAL_CONDTYPE_GE, true, "nf,vf,^,!" },
	{ "le", R_ANAL_CONDTYPE_LE, true, "zf,nf,vf,^,|" },
	{ "lt", R_ANAL_CONDTYPE_LT, true, "nf,vf,^" },
	{ "hi", R_ANAL_CONDTYPE_HI, false, "cf,zf,|,!" },
	{ "cc", R_ANAL_CONDTYPE_HS, false, "cf,!" },
	{ "ls", R_ANAL_CONDTYPE_LS, false, "cf,zf,|" },
	{ "cs", R_ANAL_CONDTYPE_LO, false, "cf" },
	{ "vc", R_ANAL_CONDTYPE_VC, false, "vf,!" },
	{ "vs", R_ANAL_CONDTYPE_VS, false, "vf" },
	{ "nc", R_ANAL_CONDTYPE_PL, false, "nf,!" },
	{ "ns", R_ANAL_CONDTYPE_MI, false, "nf" },
};

static const Mn103Cond *branch_cond(const char *name) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (mn103_conds); i++) {
		if (!strcmp (name + 1, mn103_conds[i].name)) {
			return &mn103_conds[i];
		}
	}
	return NULL;
}

static bool is_branch(const Mn103Op *o) {
	const char *n = o->in.desc->name;
	return n[0] == 'b' && strlen (n) == 3 && (!strcmp (n, "bra") || branch_cond (n));
}

static bool is_loop(const Mn103Op *o) {
	const char *n = o->in.desc->name;
	return n[0] == 'l' && strlen (n) == 3 && (!strcmp (n, "lra") || branch_cond (n));
}

static bool is_fp(const Mn103Op *o) {
	const char *n = o->in.desc->name;
	return n[0] == 'f' && strcmp (n, "fmov") != 0;
}

static const Mn103Arg *last_arg(const Mn103Op *o) {
	return o->nargs? &o->args[o->nargs - 1]: NULL;
}

static bool is_sp(const char *reg) {
	return reg && (!strcmp (reg, "sp") || !strcmp (reg, "a3"));
}

static int alu_type(const char *n) {
	if (!strcmp (n, "add") || !strcmp (n, "addc") || !strcmp (n, "inc") || !strcmp (n, "inc4")) {
		return R_ANAL_OP_TYPE_ADD;
	}
	if (!strcmp (n, "sub") || !strcmp (n, "subc")) {
		return R_ANAL_OP_TYPE_SUB;
	}
	if (!strcmp (n, "cmp")) {
		return R_ANAL_OP_TYPE_CMP;
	}
	if (!strcmp (n, "and") || !strcmp (n, "bclr")) {
		return R_ANAL_OP_TYPE_AND;
	}
	if (!strcmp (n, "or") || !strcmp (n, "bset")) {
		return R_ANAL_OP_TYPE_OR;
	}
	if (!strcmp (n, "xor")) {
		return R_ANAL_OP_TYPE_XOR;
	}
	if (!strcmp (n, "not")) {
		return R_ANAL_OP_TYPE_NOT;
	}
	if (!strcmp (n, "asl") || !strcmp (n, "asl2")) {
		return R_ANAL_OP_TYPE_SHL;
	}
	if (!strcmp (n, "asr")) {
		return R_ANAL_OP_TYPE_SAR;
	}
	if (!strcmp (n, "lsr")) {
		return R_ANAL_OP_TYPE_SHR;
	}
	if (!strcmp (n, "rol")) {
		return R_ANAL_OP_TYPE_ROL;
	}
	if (!strcmp (n, "ror")) {
		return R_ANAL_OP_TYPE_ROR;
	}
	if (!strcmp (n, "mul") || !strcmp (n, "mulu") || !strcmp (n, "mulq") || !strcmp (n, "mulqu")
		|| !strncmp (n, "mac", 3) || !strncmp (n, "dmul", 4) || !strncmp (n, "dmach", 5)) {
		return R_ANAL_OP_TYPE_MUL;
	}
	if (!strcmp (n, "div") || !strcmp (n, "divu")) {
		return R_ANAL_OP_TYPE_DIV;
	}
	if (!strcmp (n, "ext") || !strcmp (n, "extb") || !strcmp (n, "extbu") || !strcmp (n, "exth") || !strcmp (n, "exthu")) {
		return R_ANAL_OP_TYPE_CAST;
	}
	if (!strcmp (n, "btst")) {
		return R_ANAL_OP_TYPE_ACMP;
	}
	if (!strcmp (n, "clr") || !strcmp (n, "swap") || !strcmp (n, "swaph") || !strcmp (n, "swhw")
		|| !strcmp (n, "sat16") || !strcmp (n, "sat24") || !strcmp (n, "bsch")
		|| !strcmp (n, "getx") || !strcmp (n, "putx") || !strcmp (n, "getchx") || !strcmp (n, "getclx")
		|| !strncmp (n, "mcst", 4) || !strcmp (n, "setlb")) {
		return R_ANAL_OP_TYPE_MOV;
	}
	return -1;
}

static void analyze(RAnalOp *op, Mn103Op *o) {
	const char *n = o->in.desc->name;
	const Mn103Arg *a = o->args;
	const Mn103Arg *last = last_arg (o);
	op->type = R_ANAL_OP_TYPE_UNK;
	if (!strcmp (n, "nop") || !strcmp (n, "pi") || !strcmp (n, "dcpf")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (!strcmp (n, "bra")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (ut32)a[0].imm;
		op->eob = true;
	} else if (is_branch (o)) {
		const Mn103Cond *c = branch_cond (n);
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (ut32)a[0].imm;
		op->fail = o->next;
		op->cond = c->cond;
		op->sign = c->sign;
		op->eob = true;
	} else if (is_loop (o)) {
		/* the loop target is the address saved by the last setlb (register lar) */
		const Mn103Cond *c = branch_cond (n);
		op->type = c? R_ANAL_OP_TYPE_UCJMP: R_ANAL_OP_TYPE_RJMP;
		op->reg = "lar";
		if (c) {
			op->fail = o->next;
			op->cond = c->cond;
			op->sign = c->sign;
		}
		op->eob = true;
	} else if (!strcmp (n, "jmp")) {
		if (a[0].kind == ARG_PCREL) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = (ut32)a[0].imm;
		} else {
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->reg = a[0].base;
		}
		op->eob = true;
	} else if (!strcmp (n, "call")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (ut32)a[0].imm;
		op->fail = o->next;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 4 + reglist_bytes ((ut32)a[1].imm) + a[2].imm;
	} else if (!strcmp (n, "calls")) {
		if (a[0].kind == ARG_PCREL) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = (ut32)a[0].imm;
		} else {
			op->type = R_ANAL_OP_TYPE_RCALL;
			op->reg = a[0].base;
		}
		op->fail = o->next;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 4;
	} else if (!strcmp (n, "ret") || !strcmp (n, "retf")) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -(4 + reglist_bytes ((ut32)a[0].imm) + a[1].imm);
		op->eob = true;
	} else if (!strcmp (n, "rets") || !strcmp (n, "rti") || !strcmp (n, "rtm")) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = !strcmp (n, "rti")? -8: -4;
		op->eob = true;
	} else if (!strcmp (n, "trap") || !strcmp (n, "syscall")) {
		op->type = R_ANAL_OP_TYPE_SWI;
		if (o->nargs && a[0].kind == ARG_IMM) {
			op->val = a[0].imm;
		}
	} else if (!strcmp (n, "break")) {
		op->type = R_ANAL_OP_TYPE_TRAP;
	} else if (!strcmp (n, "movm")) {
		const bool push = a[0].kind == ARG_REGLIST;
		const int bytes = reglist_bytes ((ut32)(push? a[0].imm: a[1].imm));
		op->type = push? R_ANAL_OP_TYPE_RPUSH: R_ANAL_OP_TYPE_POP;
		if (is_sp (push? a[1].base: a[0].base)) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = push? bytes: -bytes;
		}
	} else if (!strcmp (n, "mov") || !strcmp (n, "movu") || !strcmp (n, "movbu") || !strcmp (n, "movhu")
		|| !strcmp (n, "fmov")) {
		const Mn103Arg *mem = NULL;
		int i;
		for (i = 0; i < o->nargs; i++) {
			if (a[i].kind == ARG_MEM) {
				mem = &a[i];
			}
		}
		if (mem) {
			const bool store = mem == last;
			op->type = store? R_ANAL_OP_TYPE_STORE: R_ANAL_OP_TYPE_LOAD;
			op->direction = store? R_ANAL_OP_DIR_WRITE: R_ANAL_OP_DIR_READ;
			op->refptr = o->access;
			op->ptrsize = o->access;
			if (mem->abs) {
				op->ptr = (ut32)mem->disp;
			} else {
				op->ireg = mem->base;
				op->disp = mem->disp;
				if (is_sp (mem->base) && !mem->index) {
					op->stackop = store? R_ANAL_STACK_SET: R_ANAL_STACK_GET;
				}
			}
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			if (a[0].kind == ARG_IMM) {
				op->val = (ut32)a[0].imm;
			}
		}
		if (is_fp (o)) {
			op->family = R_ANAL_OP_FAMILY_FPU;
		}
	} else if (is_fp (o)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		op->family = R_ANAL_OP_FAMILY_FPU;
		if (n[1] == 'b' && last && last->kind == ARG_PCREL) {
			/* fbxx: floating-point conditional branch */
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = (ut32)last->imm;
			op->fail = o->next;
			op->eob = true;
		}
	} else if (name_starts (o, "udf")) {
		op->type = R_ANAL_OP_TYPE_UNK;
	} else if (alu_type (n) >= 0) {
		op->type = alu_type (n);
		if (!strcmp (n, "clr")) {
			op->val = 0;
		} else if (o->nargs >= 2 && a[0].kind == ARG_IMM) {
			op->val = (ut32)a[0].imm;
		}
		if (o->nargs == 2 && a[0].kind == ARG_IMM && is_sp (a[1].reg)) {
			if (op->type == R_ANAL_OP_TYPE_ADD) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = -a[0].imm;
			} else if (op->type == R_ANAL_OP_TYPE_SUB) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = a[0].imm;
			}
		}
		if (last && last->kind == ARG_MEM) {
			/* bset/bclr/btst on memory */
			if (last->abs) {
				op->ptr = (ut32)last->disp;
			}
			op->refptr = 1;
		}
	} else if (strchr (n, '_')) {
		/* AM33 two-operation forms (add_add, mov_asl, ...): typed by the first operation */
		char head[16];
		const char *us = strchr (n, '_');
		size_t len = R_MIN ((size_t)(us - n), sizeof (head) - 1);
		memcpy (head, n, len);
		head[len] = 0;
		const int t = alu_type (head);
		op->type = t >= 0? (ut32)t: R_ANAL_OP_TYPE_UNK;
	}
}

/* ------------------------------------------------------------------------------------------------ ESIL */

static void esil_val(RStrBuf *sb, const Mn103Arg *a) {
	if (a->kind == ARG_REG) {
		r_strbuf_append (sb, a->reg);
	} else {
		r_strbuf_appendf (sb, "0x%x", (ut32)a->imm);
	}
}

/* push the effective address of a memory operand */
static void esil_addr(RStrBuf *sb, const Mn103Arg *m) {
	if (m->abs) {
		r_strbuf_appendf (sb, "0x%x", (ut32)m->disp);
	} else if (m->index) {
		r_strbuf_appendf (sb, "%s,%s,+", m->index, m->base);
	} else if (m->disp) {
		r_strbuf_appendf (sb, "0x%x,%s,+", (ut32)m->disp, m->base);
	} else {
		r_strbuf_append (sb, m->base);
	}
}

static void esil_postinc(RStrBuf *sb, const Mn103Arg *m, int access) {
	if (m->postinc && m->base) {
		r_strbuf_appendf (sb, ",%d,%s,+=", m->inc? m->inc: access, m->base);
	}
}

#define FLAGS_ARITH ",$z,zf,:=,31,$s,nf,:=,31,$c,cf,:=,31,$o,vf,:="
#define FLAGS_SUB ",$z,zf,:=,31,$s,nf,:=,32,$b,cf,:=,31,$o,vf,:="
#define FLAGS_LOGIC ",$z,zf,:=,31,$s,nf,:=,0,cf,:=,0,vf,:="
#define FLAGS_ZN ",$z,zf,:=,31,$s,nf,:="

static void esil_push_list(RStrBuf *sb, ut32 mask, const char *stack) {
	/* the stores are addressed from the stack pointer before the instruction (so that a pushed a3 keeps its
	 * old value); the pointer moves once at the end */
	Mn103Slot slots[32];
	const int n = reglist_slots (mask, slots, 32);
	int i;
	for (i = 0; i < n; i++) {
		if (!slots[i].dummy) {
			r_strbuf_appendf (sb, "%s,%d,%s,-,=[4],", slots[i].name, 4 * (i + 1), stack);
		}
	}
	if (n) {
		r_strbuf_appendf (sb, "%d,%s,-=,", 4 * n, stack);
	}
}

static void esil_pop_list(RStrBuf *sb, ut32 mask, const char *stack) {
	/* the loads are addressed from the stack pointer before the instruction; the final pointer adjustment is
	 * applied last, so a popped a3 is replaced by the adjusted stack pointer */
	Mn103Slot slots[32];
	const int n = reglist_slots (mask, slots, 32);
	int i;
	const bool sp = !strcmp (stack, "sp") || !strcmp (stack, "a3");
	for (i = n - 1; i >= 0; i--) {
		if (slots[i].dummy || (sp && !strcmp (slots[i].name, "a3"))) {
			continue;
		}
		r_strbuf_appendf (sb, "%d,%s,+,[4],%s,=,", 4 * (n - 1 - i), stack, slots[i].name);
	}
	if (n) {
		r_strbuf_appendf (sb, "%d,%s,+=,", 4 * n, stack);
	}
}

static void esil_extend(RStrBuf *sb, const char *reg, int bits, bool sign) {
	if (sign) {
		r_strbuf_appendf (sb, "%d,%s,~,%s,=", bits, reg, reg);
	} else {
		r_strbuf_appendf (sb, "0x%x,%s,&=", (1U << bits) - 1, reg);
	}
}

static void esil(RAnalOp *op, Mn103Op *o) {
	const char *n = o->in.desc->name;
	const Mn103Arg *a = o->args;
	const Mn103Arg *last = last_arg (o);
	RStrBuf *sb = &op->esil;
	const ut32 next = (ut32)o->next;
	const Mn103Cond *c = NULL;

	if (!strcmp (n, "nop") || !strcmp (n, "pi") || !strcmp (n, "dcpf")) {
		r_strbuf_set (sb, ",");
	} else if (!strcmp (n, "bra")) {
		r_strbuf_setf (sb, "0x%x,pc,=", (ut32)a[0].imm);
	} else if (is_branch (o) && (c = branch_cond (n))) {
		r_strbuf_setf (sb, "%s,?{,0x%x,pc,=,}", c->esil, (ut32)a[0].imm);
	} else if (!strcmp (n, "lra")) {
		r_strbuf_set (sb, "lar,pc,=");
	} else if (is_loop (o) && (c = branch_cond (n))) {
		r_strbuf_setf (sb, "%s,?{,lar,pc,=,}", c->esil);
	} else if (!strcmp (n, "setlb")) {
		r_strbuf_setf (sb, "0x%x,lar,=,0x%x,[4],lir,=", next, next);
	} else if (!strcmp (n, "jmp")) {
		if (a[0].kind == ARG_PCREL) {
			r_strbuf_setf (sb, "0x%x,pc,=", (ut32)a[0].imm);
		} else {
			r_strbuf_setf (sb, "%s,pc,=", a[0].base);
		}
	} else if (!strcmp (n, "call")) {
		r_strbuf_setf (sb, "0x%x,mdr,=,4,sp,-=,0x%x,sp,=[4],", next, next);
		esil_push_list (sb, (ut32)a[1].imm, "sp");
		r_strbuf_appendf (sb, "0x%x,sp,-=,0x%x,pc,=", (ut32)a[2].imm, (ut32)a[0].imm);
	} else if (!strcmp (n, "calls")) {
		r_strbuf_setf (sb, "0x%x,mdr,=,4,sp,-=,0x%x,sp,=[4],", next, next);
		if (a[0].kind == ARG_PCREL) {
			r_strbuf_appendf (sb, "0x%x,pc,=", (ut32)a[0].imm);
		} else {
			r_strbuf_appendf (sb, "%s,pc,=", a[0].base);
		}
	} else if (!strcmp (n, "ret") || !strcmp (n, "retf")) {
		r_strbuf_setf (sb, "0x%x,sp,+=,", (ut32)a[1].imm);
		esil_pop_list (sb, (ut32)a[0].imm, "sp");
		if (!strcmp (n, "ret")) {
			r_strbuf_append (sb, "sp,[4],pc,=,4,sp,+=");
		} else {
			r_strbuf_append (sb, "4,sp,+=,mdr,pc,=");
		}
	} else if (!strcmp (n, "rets")) {
		r_strbuf_set (sb, "sp,[4],pc,=,4,sp,+=");
	} else if (!strcmp (n, "rti")) {
		r_strbuf_set (sb, "sp,[4],epsw,=,4,sp,+=,sp,[4],pc,=,4,sp,+=");
	} else if (!strcmp (n, "movm")) {
		const bool push = a[0].kind == ARG_REGLIST;
		const char *stack = push? a[1].base: a[0].base;
		if (push) {
			esil_push_list (sb, (ut32)a[0].imm, stack);
		} else {
			esil_pop_list (sb, (ut32)a[1].imm, stack);
		}
		/* drop the trailing comma */
		char *s = r_strbuf_get (sb);
		size_t len = strlen (s);
		if (len && s[len - 1] == ',') {
			s[len - 1] = 0;
		}
	} else if (!strcmp (n, "mov") || !strcmp (n, "movu") || !strcmp (n, "movbu") || !strcmp (n, "movhu")
		|| !strcmp (n, "fmov")) {
		if (o->nargs != 2) {
			return;
		}
		if (a[1].kind == ARG_MEM) {
			esil_val (sb, &a[0]);
			r_strbuf_append (sb, ",");
			esil_addr (sb, &a[1]);
			r_strbuf_appendf (sb, ",=[%d]", o->access);
			esil_postinc (sb, &a[1], o->access);
		} else if (a[0].kind == ARG_MEM) {
			esil_addr (sb, &a[0]);
			r_strbuf_appendf (sb, ",[%d],%s,=", o->access, a[1].reg);
			esil_postinc (sb, &a[0], o->access);
		} else if (a[1].kind == ARG_REG) {
			esil_val (sb, &a[0]);
			r_strbuf_appendf (sb, ",%s,=", a[1].reg);
			if (!strcmp (a[1].reg, "pc")) {
				r_strbuf_set (sb, ",");
			}
		}
	} else if (!strcmp (n, "clr")) {
		r_strbuf_setf (sb, "0,%s,=,1,zf,:=,0,nf,:=,0,cf,:=,0,vf,:=", last->reg);
	} else if (!strcmp (n, "add") || !strcmp (n, "addc") || !strcmp (n, "sub") || !strcmp (n, "subc")
		|| !strcmp (n, "and") || !strcmp (n, "or") || !strcmp (n, "xor") || !strcmp (n, "cmp")
		|| !strcmp (n, "asl") || !strcmp (n, "asr") || !strcmp (n, "lsr") || !strcmp (n, "mulq") || !strcmp (n, "mulqu")) {
		const bool carry = !strcmp (n, "addc") || !strcmp (n, "subc");
		const char *opc = (n[0] == 'a' && n[1] == 'd')? "+": n[0] == 's'? "-": !strcmp (n, "and")? "&": !strcmp (n, "or")? "|":
			!strcmp (n, "xor")? "^": !strcmp (n, "cmp")? "=": !strcmp (n, "asl")? "<<": !strcmp (n, "asr")? ">>>>":
			!strcmp (n, "lsr")? ">>": "*";
		const char *flags = (opc[0] == '+')? FLAGS_ARITH: (opc[0] == '-' || opc[0] == '=')? FLAGS_SUB:
			(opc[0] == '&' || opc[0] == '|' || opc[0] == '^')? FLAGS_LOGIC: FLAGS_ZN;
		if (o->nargs == 3 && a[2].kind == ARG_REG) {
			/* AM33 three-operand form: rd = rn OP rm */
			esil_val (sb, &a[0]);
			r_strbuf_appendf (sb, ",%s,%s,%s,=", a[1].reg, opc, a[2].reg);
			return;
		}
		if (o->nargs != 2 || a[1].kind != ARG_REG) {
			return;
		}
		if (!strcmp (a[1].reg, "psw")) {
			esil_val (sb, &a[0]);
			r_strbuf_appendf (sb, ",psw,%s=", opc);
			return;
		}
		if (carry) {
			r_strbuf_appendf (sb, "cf,%s,%s=,", a[1].reg, opc);
		}
		esil_val (sb, &a[0]);
		r_strbuf_appendf (sb, ",%s,%s=%s", a[1].reg, opc, is_sp (a[1].reg)? "": flags);
	} else if (!strcmp (n, "inc") || !strcmp (n, "inc4")) {
		r_strbuf_setf (sb, "%d,%s,+=%s", n[3]? 4: 1, a[0].reg, (n[3] || is_sp (a[0].reg))? "": FLAGS_ARITH);
	} else if (!strcmp (n, "asl2")) {
		r_strbuf_setf (sb, "2,%s,<<=" FLAGS_ZN, a[0].reg);
	} else if (!strcmp (n, "not")) {
		r_strbuf_setf (sb, "0xffffffff,%s,^=" FLAGS_LOGIC, a[0].reg);
	} else if (!strcmp (n, "rol")) {
		r_strbuf_setf (sb, "31,%s,>>,1,&,cf,%s,<<=,1,%s,<<=,cf,%s,|=,cf,:=" FLAGS_ZN, a[0].reg, a[0].reg, a[0].reg, a[0].reg);
	} else if (!strcmp (n, "ror")) {
		r_strbuf_setf (sb, "1,%s,&,31,cf,<<,%s,>>=,1,%s,>>=,%s,|=,cf,:=" FLAGS_ZN, a[0].reg, a[0].reg, a[0].reg, a[0].reg);
	} else if (!strcmp (n, "ext")) {
		r_strbuf_setf (sb, "0x80000000,%s,&,?{,0xffffffff,mdr,=,}{,0,mdr,=,}", a[0].reg);
	} else if (!strcmp (n, "extb")) {
		esil_extend (sb, a[0].reg, 8, true);
	} else if (!strcmp (n, "extbu")) {
		esil_extend (sb, a[0].reg, 8, false);
	} else if (!strcmp (n, "exth")) {
		esil_extend (sb, a[0].reg, 16, true);
	} else if (!strcmp (n, "exthu")) {
		esil_extend (sb, a[0].reg, 16, false);
	} else if ((!strcmp (n, "mul") || !strcmp (n, "mulu")) && o->nargs == 2 && a[1].kind == ARG_REG) {
		/* mdr:dn = dn * dm */
		if (n[3]) {
			r_strbuf_setf (sb, "%s,%s,*,DUP,%s,=,32,SWAP,>>,mdr,=" FLAGS_ZN, a[0].reg, a[1].reg, a[1].reg);
		} else {
			r_strbuf_setf (sb, "32,%s,~,32,%s,~,*,DUP,%s,=,32,SWAP,>>,mdr,=" FLAGS_ZN, a[0].reg, a[1].reg, a[1].reg);
		}
	} else if ((!strcmp (n, "div") || !strcmp (n, "divu")) && o->nargs == 2 && a[1].kind == ARG_REG) {
		/* dn = (mdr:dn) / dm, mdr = remainder */
		if (n[3]) {
			r_strbuf_setf (sb, "32,mdr,<<,%s,|,DUP,%s,SWAP,%%,mdr,=,%s,SWAP,/,%s,=" FLAGS_ZN,
				a[1].reg, a[0].reg, a[0].reg, a[1].reg);
		} else {
			r_strbuf_setf (sb, "32,mdr,<<,%s,|,DUP,32,%s,~,SWAP,~%%,mdr,=,32,%s,~,SWAP,~/,%s,=" FLAGS_ZN,
				a[1].reg, a[0].reg, a[0].reg, a[1].reg);
		}
	} else if (!strcmp (n, "btst") && o->nargs == 2) {
		if (a[1].kind == ARG_MEM) {
			esil_val (sb, &a[0]);
			r_strbuf_append (sb, ",");
			esil_addr (sb, &a[1]);
			r_strbuf_append (sb, ",[1],&,DUP,!,zf,:=,0x80,&,!,!,nf,:=,0,cf,:=,0,vf,:=");
		} else {
			esil_val (sb, &a[0]);
			r_strbuf_appendf (sb, ",%s,&,DUP,!,zf,:=,0x80000000,&,!,!,nf,:=,0,cf,:=,0,vf,:=", a[1].reg);
		}
	} else if ((!strcmp (n, "bset") || !strcmp (n, "bclr")) && o->nargs == 2 && a[1].kind == ARG_MEM) {
		/* the test of the old value sets zf/nf, then the bits are set or cleared */
		esil_val (sb, &a[0]);
		r_strbuf_append (sb, ",");
		esil_addr (sb, &a[1]);
		r_strbuf_append (sb, ",[1],&,DUP,!,zf,:=,0x80,&,!,!,nf,:=,0,cf,:=,0,vf,:=,");
		esil_addr (sb, &a[1]);
		r_strbuf_append (sb, ",[1],");
		if (n[1] == 's') {
			esil_val (sb, &a[0]);
			r_strbuf_append (sb, ",|,");
		} else {
			esil_val (sb, &a[0]);
			r_strbuf_append (sb, ",0xff,^,&,");
		}
		esil_addr (sb, &a[1]);
		r_strbuf_append (sb, ",=[1]");
	} else if ((!strcmp (n, "bset") || !strcmp (n, "bclr")) && o->nargs == 2 && a[1].kind == ARG_REG) {
		esil_val (sb, &a[0]);
		if (n[1] == 's') {
			r_strbuf_appendf (sb, ",%s,|=" FLAGS_LOGIC, a[1].reg);
		} else {
			r_strbuf_appendf (sb, ",0xffffffff,^,%s,&=" FLAGS_LOGIC, a[1].reg);
		}
	} else if (!strcmp (n, "swap") && o->nargs == 2) {
		const char *s = a[0].reg, *d = a[1].reg;
		r_strbuf_setf (sb, "24,%s,<<,0xff000000,&,8,%s,<<,0xff0000,&,|,8,%s,>>,0xff00,&,|,24,%s,>>,|,%s,=", s, s, s, s, d);
	} else if (!strcmp (n, "swaph") && o->nargs == 2) {
		const char *s = a[0].reg, *d = a[1].reg;
		r_strbuf_setf (sb, "16,%s,<<,0xffff0000,&,16,%s,>>,|,%s,=", s, s, d);
	}
}

/* ------------------------------------------------------------------------------------------------ values / opex */

static void fill_values(RAnalOp *op, const Mn103Op *o) {
	int i;
	for (i = 0; i < o->nargs; i++) {
		const Mn103Arg *a = &o->args[i];
		const bool dst = i == o->nargs - 1 && o->nargs > 1 && op->type != R_ANAL_OP_TYPE_CMP
			&& op->type != R_ANAL_OP_TYPE_ACMP && op->type != R_ANAL_OP_TYPE_CALL && op->type != R_ANAL_OP_TYPE_CJMP;
		RArchValue v = { 0 };
		switch (a->kind) {
		case ARG_REG:
			v.type = R_ANAL_VAL_REG;
			v.reg = a->reg;
			break;
		case ARG_IMM:
		case ARG_PCREL:
			v.type = R_ANAL_VAL_IMM;
			v.imm = (ut32)a->imm;
			break;
		case ARG_MEM:
			v.type = R_ANAL_VAL_MEM;
			v.reg = a->base;
			v.regdelta = a->index;
			v.delta = a->disp;
			if (a->abs) {
				v.base = (ut32)a->disp;
				v.delta = 0;
			}
			v.memref = o->access;
			break;
		default:
			continue;
		}
		v.access = dst? R_PERM_W: R_PERM_R;
		if (dst) {
			RVecRArchValue_push_back (&op->dsts, &v);
			if (op->type != R_ANAL_OP_TYPE_MOV && op->type != R_ANAL_OP_TYPE_LOAD && op->type != R_ANAL_OP_TYPE_STORE) {
				v.access = R_PERM_R;
				RVecRArchValue_push_back (&op->srcs, &v);
			}
		} else {
			RVecRArchValue_push_back (&op->srcs, &v);
		}
	}
}

static void fill_opex(RAnalOp *op, const Mn103Op *o) {
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	int i;
	pj_o (pj);
	pj_ks (pj, "form", o->in.desc->name);
	pj_ki (pj, "row", o->in.index);
	pj_ka (pj, "operands");
	for (i = 0; i < o->nargs; i++) {
		const Mn103Arg *a = &o->args[i];
		pj_o (pj);
		switch (a->kind) {
		case ARG_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", a->reg);
			break;
		case ARG_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", a->imm);
			break;
		case ARG_PCREL:
			pj_ks (pj, "type", "target");
			pj_kn (pj, "value", (ut32)a->imm);
			break;
		case ARG_REGLIST:
			pj_ks (pj, "type", "reglist");
			pj_kn (pj, "value", (ut32)a->imm);
			break;
		case ARG_MEM:
			pj_ks (pj, "type", "mem");
			if (a->base) {
				pj_ks (pj, "base", a->base);
			}
			if (a->index) {
				pj_ks (pj, "index", a->index);
			}
			if (a->abs) {
				pj_kn (pj, "address", (ut32)a->disp);
			} else {
				pj_kN (pj, "disp", a->disp);
			}
			if (a->postinc) {
				pj_ki (pj, "postinc", a->inc? a->inc: o->access);
			}
			pj_ki (pj, "size", o->access);
			break;
		default:
			break;
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	r_strbuf_set (&op->opex, pj_string (pj));
	pj_free (pj);
}

/* ------------------------------------------------------------------------------------------------ plugin */

static int cpu_mach(RArchSession *s) {
	const char *cpu = s && s->config? s->config->cpu: NULL;
	if (R_STR_ISEMPTY (cpu) || !strcmp (cpu, "am33-2") || !strcmp (cpu, "am33_2") || !strcmp (cpu, "mn103")) {
		return MN103_MACH_AM33_2;
	}
	if (!strcmp (cpu, "am33")) {
		return MN103_MACH_AM33;
	}
	if (!strcmp (cpu, "am30")) {
		return MN103_MACH_AM30;
	}
	if (!strcmp (cpu, "mn10300") || !strcmp (cpu, "base")) {
		return MN103_MACH_BASE;
	}
	return MN103_MACH_AM33_2;
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	const int available = op->size;
	Mn103Op o = { 0 };
	op->type = R_ANAL_OP_TYPE_ILL;
	op->size = 1;
	op->jump = op->fail = op->ptr = op->val = UT64_MAX;
	op->eob = false;
	if (available < 1 || !op->bytes) {
		return false;
	}
	if (!mn103_decode (&o.in, op->bytes, available, op->addr, cpu_mach (s))) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	op->size = o.in.size;
	o.next = op->addr + op->size;
	build_args (&o);
	analyze (op, &o);
	op->id = o.in.index + 1;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		RStrBuf sb;
		r_strbuf_init (&sb);
		mn103_format (&sb, &o.in);
		op->mnemonic = r_strbuf_drain_nofree (&sb);
		r_strbuf_fini (&sb);
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		fill_values (op, &o);
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		fill_opex (op, &o);
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		esil (op, &o);
	}
	return true;
}

static int info(RArchSession *s, ut32 query) {
	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_FUNC_ALIGN:
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 7;
	}
	return 0;
}

static char *regs(RArchSession *s) {
	/* GCC ABI: arguments in d0, d1 (then the stack), return in d0 (pointers also in a0), a3 is the stack pointer
	 * (sp is an alias at the same offset), d2/d3/a2 callee-saved. PSW flags: Z bit 0, N bit 1, C bit 2, V bit 3. */
	return strdup (
		"=PC pc\n=SP sp\n=BP a3\n=A0 d0\n=A1 d1\n=A2 a0\n=A3 a1\n=R0 d0\n=R1 a0\n=SN d0\n"
		"gpr d0 .32 0 0\ngpr d1 .32 4 0\ngpr d2 .32 8 0\ngpr d3 .32 12 0\n"
		"gpr a0 .32 16 0\ngpr a1 .32 20 0\ngpr a2 .32 24 0\ngpr a3 .32 28 0\ngpr sp .32 28 0\n"
		"gpr pc .32 32 0\n"
		"gpr psw .32 36 0\nflg zf .1 36.0 0\nflg nf .1 36.1 0\nflg cf .1 36.2 0\nflg vf .1 36.3 0\n"
		"gpr mdr .32 40 0\ngpr lir .32 44 0\ngpr lar .32 48 0\n"
		"gpr mdrq .32 52 0\ngpr mcrh .32 56 0\ngpr mcrl .32 60 0\ngpr mcvf .32 64 0\n"
		"gpr epsw .32 68 0\ngpr usp .32 72 0\ngpr ssp .32 76 0\ngpr msp .32 80 0\n"
		"gpr r0 .32 84 0\ngpr r1 .32 88 0\ngpr r2 .32 92 0\ngpr r3 .32 96 0\n"
		"gpr r4 .32 100 0\ngpr r5 .32 104 0\ngpr r6 .32 108 0\ngpr r7 .32 112 0\n"
		"gpr xr1 .32 116 0\ngpr xr2 .32 120 0\ngpr xr3 .32 124 0\ngpr xr4 .32 128 0\n"
		"gpr xr5 .32 132 0\ngpr xr6 .32 136 0\ngpr xr7 .32 140 0\ngpr xr8 .32 144 0\n"
		"gpr xr9 .32 148 0\ngpr xr10 .32 152 0\ngpr xr11 .32 156 0\ngpr xr12 .32 160 0\n"
		"gpr xr13 .32 164 0\ngpr xr14 .32 168 0\ngpr xr15 .32 172 0\n"
		"gpr fpcr .32 176 0\n"
		"fpu fd0 .64 180 0\nfpu fs0 .32 180 0\nfpu fs1 .32 184 0\n"
		"fpu fd2 .64 188 0\nfpu fs2 .32 188 0\nfpu fs3 .32 192 0\n"
		"fpu fd4 .64 196 0\nfpu fs4 .32 196 0\nfpu fs5 .32 200 0\n"
		"fpu fd6 .64 204 0\nfpu fs6 .32 204 0\nfpu fs7 .32 208 0\n"
		"fpu fd8 .64 212 0\nfpu fs8 .32 212 0\nfpu fs9 .32 216 0\n"
		"fpu fd10 .64 220 0\nfpu fs10 .32 220 0\nfpu fs11 .32 224 0\n"
		"fpu fd12 .64 228 0\nfpu fs12 .32 228 0\nfpu fs13 .32 232 0\n"
		"fpu fd14 .64 236 0\nfpu fs14 .32 236 0\nfpu fs15 .32 240 0\n"
		"fpu fd16 .64 244 0\nfpu fs16 .32 244 0\nfpu fs17 .32 248 0\n"
		"fpu fd18 .64 252 0\nfpu fs18 .32 252 0\nfpu fs19 .32 256 0\n"
		"fpu fd20 .64 260 0\nfpu fs20 .32 260 0\nfpu fs21 .32 264 0\n"
		"fpu fd22 .64 268 0\nfpu fs22 .32 268 0\nfpu fs23 .32 272 0\n"
		"fpu fd24 .64 276 0\nfpu fs24 .32 276 0\nfpu fs25 .32 280 0\n"
		"fpu fd26 .64 284 0\nfpu fs26 .32 284 0\nfpu fs27 .32 288 0\n"
		"fpu fd28 .64 292 0\nfpu fs28 .32 292 0\nfpu fs29 .32 296 0\n"
		"fpu fd30 .64 300 0\nfpu fs30 .32 300 0\nfpu fs31 .32 304 0\n");
}

RArchPlugin r_arch_plugin_mn103 = {
	.meta = {
		.name = "mn103",
		.desc = "Panasonic MN10300 / AM30 / AM33 / AM33-2 (GNU binutils opcode table)",
		.author = "n0p",
		.license = "GPL-3.0-or-later",
	},
	.arch = "mn103",
	.cpus = "am33-2,am33,am30,mn10300",
	.bits = R_SYS_BITS_PACK1 (32),
	.addr_bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = decode,
	.info = info,
	.regs = regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_mn103,
	.version = R2_VERSION
};
#endif
