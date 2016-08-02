/* radare2 - BSD - Copyright 2016 - ibabushkin */

#include <stdio.h>
#include <r_anal.h>
#include "anal.h"
#include "asm.h"

static ut64 get_type(agc_insn_type type) {
	switch (type) {
	// arithmetic instructions
	case AGC_INSN_DDOUBL: // double `A`, `L` register pair
	case AGC_INSN_DOUBLE: // double `A` register
	case AGC_INSN_INDEX: // add value to next instruction
	case AGC_INSN_DAS: // add `A`, `L` register pair to memory
	case AGC_INSN_INCR: // increment
	case AGC_INSN_ADS: // add `A` register to memory
	case AGC_INSN_AD: // add memory to the `A` register
	case AGC_INSN_AUG: // "augment" a value
	case AGC_INSN_DIM: // "diminish" a value
		return R_ANAL_OP_TYPE_ADD;
	case AGC_INSN_MSU: // special kind of difference
	case AGC_INSN_SU: // subtract memory from `A` register
		return R_ANAL_OP_TYPE_SUB;
	case AGC_INSN_SQUARE: // square the `A` register
	case AGC_INSN_MP: // multiply with `A` register
		return R_ANAL_OP_TYPE_MUL;
	case AGC_INSN_DV: // divide `A`, `L` by memory location, write back
					  // results (quotient and remainder)
		return R_ANAL_OP_TYPE_DIV;
	// bitwise logic
	case AGC_INSN_COM: // complement `A` register
	case AGC_INSN_CS: // move complement into `A` register
	case AGC_INSN_DCOM: // complement `A`, `L` register pair
	case AGC_INSN_DCS: // move complement into `A`, `L` register pair
		return R_ANAL_OP_TYPE_CPL;
	case AGC_INSN_MASK: // logically and a value in memory
		return R_ANAL_OP_TYPE_AND;
	// control flow and interrupts
	case AGC_INSN_TCF: // jump to fixed memory
		return R_ANAL_OP_TYPE_JMP;
	case AGC_INSN_OVSK: // skip next instruction on overflow
	case AGC_INSN_CCS: // conditional jump to erasable memory
	case AGC_INSN_BZF: // branch to fixed memory if `A` = 0
	case AGC_INSN_BZMF: // branch to fixed memory if `A` <= 0
		return R_ANAL_OP_TYPE_CJMP;
	case AGC_INSN_TCAA: // jump to address in `A`
	case AGC_INSN_XLQ: // jump to `A`
	case AGC_INSN_XXALQ: // jump to `A` with extracode
		return R_ANAL_OP_TYPE_UCJMP;
	case AGC_INSN_TC: // call subroutine
		return R_ANAL_OP_TYPE_CALL;
	case AGC_INSN_RETURN: // return from subroutine
		return R_ANAL_OP_TYPE_RET;
	case AGC_INSN_INHINT: // diable interrupts
	case AGC_INSN_RELINT: // enable interrupts
	case AGC_INSN_RESUME: // resume after an ISR
	case AGC_INSN_EXTEND: // extend next instruction
						  // (not directly interrupt-related)
		return R_ANAL_OP_TYPE_SWI;
	// moving memory
	case AGC_INSN_TS: // transfer to storage and manipulate `A`
		return R_ANAL_OP_TYPE_CMOV; // TODO: maybe make it STORE?
	case AGC_INSN_CA: // move memory into the `A` register
	case AGC_INSN_DCA: // move memory into `A`, `L` register pair
		return R_ANAL_OP_TYPE_LOAD;
	case AGC_INSN_DTCB: // memory adressing change using a register swap
	case AGC_INSN_DTCF: // similar to the above
	case AGC_INSN_ZL: // clear `L` register
	case AGC_INSN_ZQ: // clear `Q` register
	case AGC_INSN_LXCH: // exchange with `L` register
	case AGC_INSN_DXCH: // exchange with `A`, `L` register pair
	case AGC_INSN_XCH: // exchange with `A` register
	case AGC_INSN_QXCH: // exchange with `Q` register
		return R_ANAL_OP_TYPE_XCHG;
	// special instructions and I/O
	case AGC_INSN_NOOP: // do nothing
		return R_ANAL_OP_TYPE_NOP;
	case AGC_INSN_READ: // read IO channel into `A`
	case AGC_INSN_WRITE: // write contents of `A` into IO channel
	case AGC_INSN_RAND: // read IO channel into `A`, with and
	case AGC_INSN_WAND: // write contents of `A` into IO channel, with and
	case AGC_INSN_ROR: // read IO channel into `A`, with or
	case AGC_INSN_WOR: // write contents of `A` into IO channel, with or
	case AGC_INSN_RXOR: // read IO channel into `A`, with xor
		return R_ANAL_OP_TYPE_IO;
	case AGC_INSN_EDRUPT: // we don't know what it does
	default:
		return R_ANAL_OP_TYPE_UNK;
	}
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC	Z\n"
		"=SP	Q\n"
		"gpr	A	.16	0	0\n" // TODO: model overflow bit
		"gpr	L	.16	2	0\n" // TODO: model overflow bit
		"gpr	Q	.16	4	0\n" // TODO: model overflow bit
		"seg	EB	.15	6	0\n" // TODO: model mirroring
		"seg	FB	.15	8	0\n" // TODO: model mirroring
		"gpr	Z	.12	10	0\n" // ...
		"seg	BB	.15	12	0\n" // TODO: model mirroring
		// TODO: model 7th 0-register?
		"gpr	ARUPT	.15	14	0\n"
		"gpr	LRUPT	.15	16	0\n"
		"gpr	QRUPT	.15	18	0\n"
		"gpr	ZRUPT	.15	20	0\n"
		"gpr	BBRUPT	.15	22	0\n"
		"gpr	BRUPT	.15	24	0\n"
		// TODO: model editing registers
		// TODO: model timer and counter registers?
	;
	return r_reg_set_profile_string (anal->reg, p);
}

static bool get_esil(RAnalOp *op, const agc_insn_t *insn) {
	// TODO: account for weird addressing scheme!
	r_strbuf_init (&op->esil);
	r_strbuf_set  (&op->esil, "");

	// TODO: implement flag behaviours!
	switch (insn->type) {
	case AGC_INSN_COM:
		r_strbuf_set (&op->esil, "A,!=");
		break;
	case AGC_INSN_DDOUBL:
		// TODO: find a way to implement
		break;
	case AGC_INSN_DOUBLE:
		r_strbuf_set (&op->esil, "2,A,*=");
		break;
	case AGC_INSN_DTCB:
	case AGC_INSN_DTCF:
	case AGC_INSN_EXTEND:
	case AGC_INSN_INHINT:
		// TODO: find a way to implement
		break;
	case AGC_INSN_NOOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case AGC_INSN_OVSK:
		r_strbuf_set (&op->esil, "a_overflow,?{,2,Z,+=,}"); // FIXME
		break;
	case AGC_INSN_RELINT:
	case AGC_INSN_RESUME: // TODO: handle extracode
		// TODO: find a way to implement
		break;
	case AGC_INSN_RETURN:
		r_strbuf_set (&op->esil, "Q,Z,=,00003,Q,=");
		break;
	case AGC_INSN_TCAA:
		// TODO: find a way to implement
		break;
	case AGC_INSN_XLQ:
		r_strbuf_set (&op->esil, "2,$$,+,Q,=,1,Z,=");
		break;
	case AGC_INSN_XXALQ:
		r_strbuf_set (&op->esil, "2,$$,+,Q,=,0,Z,=");
		break;
	case AGC_INSN_ZL:
		r_strbuf_set (&op->esil, "0,L,=");
		break;
	case AGC_INSN_TC:
		r_strbuf_setf (&op->esil, "2,$$,+,Q,=,%04o,Z,=", insn->operand);
		break;
	case AGC_INSN_CCS:
		// TODO: find a way to implement
		break;
	case AGC_INSN_TCF:
		r_strbuf_setf (&op->esil, "%04o,Z,=", insn->operand);
		break;
	case AGC_INSN_DAS:
	case AGC_INSN_LXCH:
		// TODO: find a way to implement
		break;
	case AGC_INSN_INCR:
		r_strbuf_setf (&op->esil,
				"%04o,[],++,%04o,=[]", insn->operand, insn->operand);
		break;
	case AGC_INSN_ADS:
		r_strbuf_setf (&op->esil,
				"%04o,[],A,+,A,%04o,[]=", insn->operand, insn->operand);
		break;
	case AGC_INSN_CA:
		r_strbuf_setf (&op->esil, "%04o,[],A,=", insn->operand);
		break;
	case AGC_INSN_CS:
		r_strbuf_setf (&op->esil, "%04o,[],!,A,=", insn->operand);
		break;
	case AGC_INSN_INDEX: // TODO: handle extracode
	case AGC_INSN_DXCH:
	case AGC_INSN_TS:
	case AGC_INSN_XCH:
		// TODO: find a way to implement
		break;
	case AGC_INSN_AD:
		r_strbuf_setf (&op->esil, "%04o,[],A,+=", insn->operand);
		break;
	case AGC_INSN_MASK:
		r_strbuf_setf (&op->esil, "%04o,[],A,&=", insn->operand);
		break;
	case AGC_INSN_DCOM: // TODO: handle extracode flag from here on
		r_strbuf_set (&op->esil, "A,!=,L,!=");
		break;
	case AGC_INSN_SQUARE:
		r_strbuf_set (&op->esil, "A,A,*=");
		break;
	case AGC_INSN_ZQ:
		r_strbuf_set (&op->esil, "0,A,=");
	case AGC_INSN_READ:
	case AGC_INSN_WRITE:
	case AGC_INSN_RAND:
	case AGC_INSN_WAND:
	case AGC_INSN_ROR:
	case AGC_INSN_WOR:
	case AGC_INSN_RXOR:
	case AGC_INSN_EDRUPT:
	case AGC_INSN_DV:
		// TODO: find a way to implement
		break;
	case AGC_INSN_BZF:
		r_strbuf_setf (&op->esil, "0,A,==,?,{,%04o,Z,=,}", insn->operand);
		break;
	case AGC_INSN_MSU:
	case AGC_INSN_QXCH:
	case AGC_INSN_AUG:
	case AGC_INSN_DIM:
	case AGC_INSN_DCA:
	case AGC_INSN_DCS:
		// TODO: find a way to implement
		break;
	case AGC_INSN_SU:
		r_strbuf_setf (&op->esil, "%04o,A,-=", insn->operand);
		break;
	case AGC_INSN_BZMF:
		r_strbuf_setf (&op->esil, "0,A,<=,?,{,%04o,Z,=,}", insn->operand);
		break;
	case AGC_INSN_MP:
		r_strbuf_setf (&op->esil, "%04o,A,*=", insn->operand);
		break;

	default:
		return false;
	}
	return true;
}

void analyze_agc_insn(RAnalOp *op, ut64 address, ut16 value, bool shift) {

	agc_insn_t insn = {0};
	disasm_agc_insn (&insn, address, value, shift);

	op->size = 2;
	op->type = get_type (insn.type);
}
