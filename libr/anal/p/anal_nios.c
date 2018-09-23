/* nios plugin by hewittc at 2018 */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "dis-asm.h"

#include "nios/gnu/nios-desc.h"

#define OP_SIZE 1024
#define OP_TYPES 6

#define f_op11(i)   ((i >> 5))
#define f_op9(i)    ((i >> 7))
#define f_op8(i)    ((i >> 8))
#define f_op6(i)    ((i >> 10))
#define f_op5w(i)   ((i >> 5)  & 0x001f)
#define f_op5(i)    ((i >> 11))
#define f_op4(i)    ((i >> 12))
#define f_op3u(i)   ((i >> 7)  & 0x0007)
#define f_op3(i)    ((i >> 13))
#define f_op2v(i)   ((i >> 8)  & 0x0003)

#define f_IMM11(i)  ((i >> 0)  & 0x07ff)
#define f_IMM10(i)  ((i >> 0)  & 0x03ff)
#define f_IMM9(i)   ((i >> 1)  & 0x01ff)
#define f_IMM8v(i)  ((i >> 0)  & 0x00ff)
#define f_IMM8(i)   ((i >> 5)  & 0x00ff)
#define f_IMM6v(i)  ((i >> 0)  & 0x003f)
#define f_IMM6(i)   ((i >> 5)  & 0x003f)
#define f_IMM5(i)   ((i >> 5)  & 0x001f)
#define f_IMM4w(i)  ((i >> 0)  & 0x00ff)
#define f_IMM4(i)   ((i >> 5)  & 0x000f)
#define f_IMM2u(i)  ((i >> 5)  & 0x0003)
#define f_IMM1u(i)  ((i >> 6)  & 0x0001)

#define f_P(i)      ((i >> 10) & 0x0003)
#define f_B(i)      ((i >> 5)  & 0x001f)
#define f_A(i)      ((i >> 0)  & 0x001f)

enum insn_format {
	FMT_UNKNOWN,
	FMT_RR,
	FMT_Ri5,
	FMT_Ri4,
	FMT_RPi5,
	FMT_Ri6,
	FMT_Ri8,
	FMT_i9,
	FMT_i10,
	FMT_i11,
	FMT_Ri1u,
	FMT_Ri2u,
	FMT_i8v,
	FMT_i6v,
	FMT_Rw,
	FMT_i4w,
	FMT_w
};

enum insn_type {
	TYPE_UNKNOWN,
	TYPE_OP11,
	TYPE_OP9,
	TYPE_OP8,
	TYPE_OP5,
	TYPE_OP4,
	TYPE_OP3,
	TYPE_OP6
};

struct insn_fields {
	ut16 op11;
	ut16 op9;
	ut16 op8;
	ut16 op6;
	ut16 op5w;
	ut16 op5;
	ut16 op4;
	ut16 op3u;
	ut16 op3;
	ut16 op2v;

	ut16 IMM11;
	ut16 IMM10;
	ut16 IMM9;
	ut16 IMM8v;
	ut16 IMM8;
	ut16 IMM6v;
	ut16 IMM6;
	ut16 IMM5;
	ut16 IMM4w;
	ut16 IMM4;
	ut16 IMM2u;
	ut16 IMM1u;

	ut16 P;
	ut16 B;
	ut16 A;
};

struct nios_op {
	_RAnalOpType type;
	enum insn_type type_op;
	enum insn_format format;
};

static struct nios_op nios16_ops[OP_SIZE] = {
	// op6
	[OP_ADD]     = { R_ANAL_OP_TYPE_ADD,   TYPE_OP6,  FMT_RR },
	[OP_ADDI]    = { R_ANAL_OP_TYPE_ADD,   TYPE_OP6,  FMT_Ri5 },
	[OP_SUB]     = { R_ANAL_OP_TYPE_SUB,   TYPE_OP6,  FMT_RR },
	[OP_SUBI]    = { R_ANAL_OP_TYPE_SUB,   TYPE_OP6,  FMT_Ri5 },
	[OP_CMP]     = { R_ANAL_OP_TYPE_CMP,   TYPE_OP6,  FMT_RR },
	[OP_CMPI]    = { R_ANAL_OP_TYPE_CMP,   TYPE_OP6,  FMT_Ri5 },
	[OP_LSL]     = { R_ANAL_OP_TYPE_SHL,   TYPE_OP6,  FMT_RR },
	[OP_LSLI]    = { R_ANAL_OP_TYPE_SHL,   TYPE_OP6,  FMT_Ri4 },
	[OP_LSR]     = { R_ANAL_OP_TYPE_SHR,   TYPE_OP6,  FMT_RR },
	[OP_LSRI]    = { R_ANAL_OP_TYPE_SHR,   TYPE_OP6,  FMT_Ri4 },
	[OP_ASR]     = { R_ANAL_OP_TYPE_SAR,   TYPE_OP6,  FMT_RR },
	[OP_ASRI]    = { R_ANAL_OP_TYPE_SAR,   TYPE_OP6,  FMT_Ri4 },
	[OP_MOV]     = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_MOVI]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_Ri5 },
	[OP_AND]     = { R_ANAL_OP_TYPE_AND,   TYPE_OP6,  FMT_RR },
	[OP_ANDN]    = { R_ANAL_OP_TYPE_AND,   TYPE_OP6,  FMT_RR },
	[OP_OR]      = { R_ANAL_OP_TYPE_OR,    TYPE_OP6,  FMT_RR },
	[OP_XOR]     = { R_ANAL_OP_TYPE_XOR,   TYPE_OP6,  FMT_RR },
	[OP_BGEN]    = { R_ANAL_OP_TYPE_MUL,   TYPE_OP6,  FMT_Ri4 },
	[OP_EXT8D]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_SKP0]    = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP6,  FMT_Ri4 },
	[OP_SKP1]    = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP6,  FMT_Ri4 },
	[OP_LD]      = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP6,  FMT_RR },
	[OP_ST]      = { R_ANAL_OP_TYPE_STORE, TYPE_OP6,  FMT_RR },
	[OP_STS8S]   = { R_ANAL_OP_TYPE_STORE, TYPE_OP6,  FMT_i10 },
	[OP_ADDC]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_SUBC]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_Ri5 },
	[OP_USR0]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP6,  FMT_RR },
	// op3
	[OP_STS]     = { R_ANAL_OP_TYPE_STORE, TYPE_OP3,  FMT_Ri8 },
	[OP_LDS]     = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP3,  FMT_Ri8 },
	// op4
	[OP_STP]     = { R_ANAL_OP_TYPE_STORE, TYPE_OP4,  FMT_RPi5 },
	[OP_LDP]     = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP4,  FMT_RPi5 },
	// op5
	[OP_BR]      = { R_ANAL_OP_TYPE_JMP,   TYPE_OP5,  FMT_i11 },
	[OP_BSR]     = { R_ANAL_OP_TYPE_JMP,   TYPE_OP5,  FMT_i11 },
	[OP_PFX]     = { R_ANAL_OP_TYPE_MOV,   TYPE_OP5,  FMT_i11 },
	// op8
	[OP_SAVE]    = { R_ANAL_OP_TYPE_PUSH,  TYPE_OP8,  FMT_i8v },
	[OP_TRAP]    = { R_ANAL_OP_TYPE_TRAP,  TYPE_OP8,  FMT_i6v },
	// op9
	[OP_EXT8S]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP9,  FMT_Ri1u },
	[OP_ST8S]    = { R_ANAL_OP_TYPE_STORE, TYPE_OP9,  FMT_Ri1u },
	// op11
	[OP_NOT]     = { R_ANAL_OP_TYPE_NOT,   TYPE_OP11, FMT_Rw },
	[OP_NEG]     = { R_ANAL_OP_TYPE_SUB,   TYPE_OP11, FMT_Rw },
	[OP_ABS]     = { R_ANAL_OP_TYPE_ABS,   TYPE_OP11, FMT_Rw },
	[OP_SEXT8]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_RLC]     = { R_ANAL_OP_TYPE_ROL,   TYPE_OP11, FMT_Rw },
	[OP_RRC]     = { R_ANAL_OP_TYPE_ROR,   TYPE_OP11, FMT_Rw },
	[OP_TRET]    = { R_ANAL_OP_TYPE_UJMP,  TYPE_OP11, FMT_Rw },
	[OP_RESTORE] = { R_ANAL_OP_TYPE_POP,   TYPE_OP11, FMT_w },
	[OP_ST8D]    = { R_ANAL_OP_TYPE_STORE, TYPE_OP11, FMT_Rw },
	[OP_FILL8]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_SKPRZ]   = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_SKPS]    = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_WRCTL]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_RDCTL]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_SKPRNZ]  = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP11, FMT_Rw },
	[OP_JMP]     = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_CALL]    = { R_ANAL_OP_TYPE_CALL,  TYPE_OP11, FMT_Rw },
	[OP_SWAP]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_USR1]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR2]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR3]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR4]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
};

static struct nios_op nios32_ops[OP_SIZE] = {
	// op6
	[OP_ADD]     = { R_ANAL_OP_TYPE_ADD,   TYPE_OP6,  FMT_RR },
	[OP_ADDI]    = { R_ANAL_OP_TYPE_ADD,   TYPE_OP6,  FMT_Ri5 },
	[OP_SUB]     = { R_ANAL_OP_TYPE_SUB,   TYPE_OP6,  FMT_RR },
	[OP_SUBI]    = { R_ANAL_OP_TYPE_SUB,   TYPE_OP6,  FMT_Ri5 },
	[OP_CMP]     = { R_ANAL_OP_TYPE_CMP,   TYPE_OP6,  FMT_RR },
	[OP_CMPI]    = { R_ANAL_OP_TYPE_CMP,   TYPE_OP6,  FMT_Ri5 },
	[OP_LSL]     = { R_ANAL_OP_TYPE_SHL,   TYPE_OP6,  FMT_RR },
	[OP_LSLI]    = { R_ANAL_OP_TYPE_SHL,   TYPE_OP6,  FMT_Ri5 },
	[OP_LSR]     = { R_ANAL_OP_TYPE_SHR,   TYPE_OP6,  FMT_RR },
	[OP_LSRI]    = { R_ANAL_OP_TYPE_SHR,   TYPE_OP6,  FMT_Ri5 },
	[OP_ASR]     = { R_ANAL_OP_TYPE_SAR,   TYPE_OP6,  FMT_RR },
	[OP_ASRI]    = { R_ANAL_OP_TYPE_SAR,   TYPE_OP6,  FMT_Ri5 },
	[OP_MOV]     = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_MOVI]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_Ri5 },
	[OP_AND]     = { R_ANAL_OP_TYPE_AND,   TYPE_OP6,  FMT_RR },
	[OP_ANDN]    = { R_ANAL_OP_TYPE_AND,   TYPE_OP6,  FMT_RR },
	[OP_OR]      = { R_ANAL_OP_TYPE_OR,    TYPE_OP6,  FMT_RR },
	[OP_XOR]     = { R_ANAL_OP_TYPE_XOR,   TYPE_OP6,  FMT_RR },
	[OP_BGEN]    = { R_ANAL_OP_TYPE_MUL,   TYPE_OP6,  FMT_Ri5 },
	[OP_EXT8D]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_SKP0]    = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP6,  FMT_Ri5 },
	[OP_SKP1]    = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP6,  FMT_Ri5 },
	[OP_LD]      = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP6,  FMT_RR },
	[OP_ST]      = { R_ANAL_OP_TYPE_STORE, TYPE_OP6,  FMT_RR },
	[OP_STS8S]   = { R_ANAL_OP_TYPE_STORE, TYPE_OP6,  FMT_i10 },
	[OP_STS16S]  = { R_ANAL_OP_TYPE_STORE, TYPE_OP6,  FMT_i9 },
	[OP_EXT16D]  = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_RR },
	[OP_MOVHI]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP6,  FMT_Ri5 },
	[OP_USR0]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP6,  FMT_RR },
	// op3
	[OP_STS]     = { R_ANAL_OP_TYPE_STORE, TYPE_OP3,  FMT_Ri8 },
	[OP_LDS]     = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP3,  FMT_Ri8 },
	// op4
	[OP_STP]     = { R_ANAL_OP_TYPE_STORE, TYPE_OP4,  FMT_RPi5 },
	[OP_LDP]     = { R_ANAL_OP_TYPE_LOAD,  TYPE_OP4,  FMT_RPi5 },
	// op5
	[OP_BR]      = { R_ANAL_OP_TYPE_JMP,   TYPE_OP5,  FMT_i11 },
	[OP_BSR]     = { R_ANAL_OP_TYPE_JMP,   TYPE_OP5,  FMT_i11 },
	[OP_PFXIO]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP5,  FMT_i11 },
	[OP_PFX]     = { R_ANAL_OP_TYPE_MOV,   TYPE_OP5,  FMT_i11 },
	// op8
	[OP_SAVE]    = { R_ANAL_OP_TYPE_PUSH,  TYPE_OP8,  FMT_i8v },
	[OP_TRAP]    = { R_ANAL_OP_TYPE_TRAP,  TYPE_OP8,  FMT_i6v },
	// op9
	[OP_EXT8S]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP9,  FMT_Ri1u },
	[OP_EXT16S]  = { R_ANAL_OP_TYPE_MOV,   TYPE_OP9,  FMT_Ri1u },
	[OP_ST8S]    = { R_ANAL_OP_TYPE_STORE, TYPE_OP9,  FMT_Ri1u },
	[OP_ST16S]   = { R_ANAL_OP_TYPE_STORE, TYPE_OP9,  FMT_Ri1u },
	// op11
	[OP_NOT]     = { R_ANAL_OP_TYPE_NOT,   TYPE_OP11, FMT_Rw },
	[OP_NEG]     = { R_ANAL_OP_TYPE_SUB,   TYPE_OP11, FMT_Rw },
	[OP_ABS]     = { R_ANAL_OP_TYPE_ABS,   TYPE_OP11, FMT_Rw },
	[OP_SEXT8]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_SEXT16]  = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_RLC]     = { R_ANAL_OP_TYPE_ROL,   TYPE_OP11, FMT_Rw },
	[OP_RRC]     = { R_ANAL_OP_TYPE_ROR,   TYPE_OP11, FMT_Rw },
	[OP_TRET]    = { R_ANAL_OP_TYPE_UJMP,  TYPE_OP11, FMT_Rw },
	[OP_RESTORE] = { R_ANAL_OP_TYPE_POP,   TYPE_OP11, FMT_w },
	[OP_ST8D]    = { R_ANAL_OP_TYPE_STORE, TYPE_OP11, FMT_Rw },
	[OP_ST16D]   = { R_ANAL_OP_TYPE_STORE, TYPE_OP11, FMT_Rw },
	[OP_FILL8]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_FILL16]  = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_SKPRZ]   = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_SKPS]    = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_WRCTL]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_RDCTL]   = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_SKPRNZ]  = { R_ANAL_OP_TYPE_CJMP,  TYPE_OP11, FMT_Rw },
	[OP_JMP]     = { R_ANAL_OP_TYPE_JMP,   TYPE_OP11, FMT_Rw },
	[OP_CALL]    = { R_ANAL_OP_TYPE_CALL,  TYPE_OP11, FMT_Rw },
	[OP_SWAP]    = { R_ANAL_OP_TYPE_MOV,   TYPE_OP11, FMT_Rw },
	[OP_USR1]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR2]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR3]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_USR4]    = { R_ANAL_OP_TYPE_IO,    TYPE_OP11, FMT_Rw },
	[OP_MSTEP]   = { R_ANAL_OP_TYPE_MUL,   TYPE_OP11, FMT_Rw },
	[OP_MUL]     = { R_ANAL_OP_TYPE_MUL,   TYPE_OP11, FMT_Rw }
};

static struct nios_op *nios_ops;

static int parse_insn(int bits, ut16 insn, struct insn_fields *f) {
	int opcode;
	opcode = -1;

	ut16 insns[OP_TYPES] = {
		f_op6(insn),
		f_op9(insn),
		f_op11(insn),
		f_op5(insn),
		f_op4(insn),
		f_op3(insn)
	};

	int op;
	for (int i = 0; i < OP_TYPES; i++) {
		op = insns[i];
		eprintf("%d ", op);
		if (op < OP_SIZE && nios_ops[op].format) {
			opcode = op;
			eprintf("break\n");
			break;
		}
	}

	eprintf("opcode %d: format: %d, type: %d\n", opcode, nios_ops[opcode].format, nios_ops[opcode].type_op);

	switch (nios_ops[opcode].format) {
	case FMT_RR:
		f->op6 = f_op6(insn);
		f->B = f_B(insn);
		f->A = f_A(insn);
		break;

	case FMT_Ri5:
		f->op6 = f_op6(insn);
		f->IMM5 = f_IMM5(insn);
		f->A = f_A(insn);
		break;

	case FMT_Ri4:
		f->op6 = f_op6(insn);
		f->IMM4 = f_IMM4(insn);
		f->A = f_A(insn);
		break;

	case FMT_RPi5:
		f->op4 = f_op4(insn);
		f->P = f_P(insn);
		f->B = f_B(insn);
		f->A = f_A(insn);
		break;
		
	case FMT_Ri6:
		f->op5 = f_op5(insn);
		f->IMM6 = f_IMM6(insn);
		f->A = f_A(insn);
		break;
		
	case FMT_Ri8:
		f->op3 = f_op3(insn);
		f->IMM8 = f_IMM8(insn);
		f->A = f_A(insn);
		break;

	case FMT_i9:
		f->op6 = f_op6(insn);
		f->IMM9 = f_IMM9(insn);
		break;

	case FMT_i10:
		f->op6 = f_op6(insn);
		f->IMM10 = f_IMM10(insn);
		break;

	case FMT_i11:
		f->op5 = f_op5(insn);
		f->IMM11 = f_IMM11(insn);
		break;

	case FMT_Ri1u:
		f->op6 = f_op6(insn);
		f->op3u = f_op3u(insn);
		f->IMM1u = f_IMM1u(insn);
		f->A = f_A(insn);
		break;

	case FMT_Ri2u:
		f->op6 = f_op6(insn);
		f->op3u = f_op3u(insn);
		f->IMM2u = f_IMM2u(insn);
		f->A = f_A(insn);
		break;

	case FMT_i8v:
		f->op6 = f_op6(insn);
		f->op2v = f_op2v(insn);
		f->IMM8v = f_IMM8v(insn);
		break;

	case FMT_i6v:
		f->op6 = f_op6(insn);
		f->op2v = f_op2v(insn);
		f->IMM6v = f_IMM6v(insn);
		break;

	case FMT_Rw:
		f->op6 = f_op6(insn);
		f->op5w = f_op5w(insn);
		f->A = f_A(insn);
		break;

	case FMT_i4w:
		f->op6 = f_op6(insn);
		f->op5w = f_op5w(insn);
		f->IMM4w = f_IMM4w(insn);
		break;

	case FMT_w:
		f->op6 = f_op6(insn);
		f->op5w = f_op5w(insn);
		break;

	case FMT_UNKNOWN:
	default:
		break;
	}

	return opcode;
}

static void nios16_anal(RAnalOp *op, int opcode, enum insn_type type, struct insn_fields *f) {
	if (type == TYPE_OP6) {
		switch (opcode) {
		case OP_ADD:
		case OP_ADDI:
		case OP_SUB:
		case OP_SUBI:
		case OP_CMP:
		case OP_CMPI:
		case OP_LSL:
		case OP_LSLI:
		case OP_LSR:
		case OP_LSRI:
		case OP_ASR:
		case OP_ASRI:
		case OP_MOV:
		case OP_MOVI:
		case OP_AND:
		case OP_ANDN:
		case OP_OR:
		case OP_XOR:
		case OP_BGEN:
		case OP_EXT8D:
		case OP_SKP0:
		case OP_SKP1:
		case OP_LD:
		case OP_ST:
		case OP_STS8S:
		case OP_ADDC:
		case OP_SUBC:
		case OP_USR0:
		default:
			break;
		}
	} else if (type == TYPE_OP3) {
		switch (opcode) {
		case OP_STS:
		case OP_LDS:
		default:
			break;
		}
	} else if (type == TYPE_OP4) {
		switch (opcode) {
		case OP_STP:
		case OP_LDP:
		default:
			break;
		}
	} else if (type == TYPE_OP5) {
		switch (opcode) {
		case OP_BR:
		case OP_BSR:
		case OP_PFX:
		default:
			break;
		}
	} else if (type == TYPE_OP8) {
		switch (opcode) {
		case OP_SAVE:
		case OP_TRAP:
			break;
		}
	} else if (type == TYPE_OP9) {
		switch (opcode) {
		case OP_EXT8S:
		case OP_ST8S:
		default:
			break;
		}
	} else if (type == TYPE_OP11) {
		switch (opcode) {
		case OP_NOT:
		case OP_NEG:
		case OP_ABS:
		case OP_SEXT8:
		case OP_RLC:
		case OP_RRC:
		case OP_TRET:
		case OP_RESTORE:
		case OP_ST8D:
		case OP_FILL8:
		case OP_SKPRZ:
		case OP_SKPS:
		case OP_WRCTL:
		case OP_RDCTL:
		case OP_SKPRNZ:
		case OP_JMP:
		case OP_CALL:
		case OP_SWAP:
		case OP_USR1:
		case OP_USR2:
		case OP_USR3:
		case OP_USR4:
		default:
			break;
		}
	}
}

static void nios32_anal(RAnalOp *op, int opcode, enum insn_type type, struct insn_fields *f) {
	if (type == TYPE_OP6) {
		switch (opcode) {
		case OP_ADD:
		case OP_ADDI:
		case OP_SUB:
		case OP_SUBI:
		case OP_CMP:
		case OP_CMPI:
		case OP_LSL:
		case OP_LSLI:
		case OP_LSR:
		case OP_LSRI:
		case OP_ASR:
		case OP_ASRI:
		case OP_MOV:
		case OP_MOVI:
		case OP_AND:
		case OP_ANDN:
			break;
		case OP_OR:
			eprintf("OR!\n");
			break;
		case OP_XOR:
		case OP_BGEN:
		case OP_EXT8D:
		case OP_SKP0:
		case OP_SKP1:
		case OP_LD:
		case OP_ST:
		case OP_STS8S:
		case OP_STS16S:
		case OP_EXT16D:
		case OP_MOVHI:
		case OP_USR0:
		default:
			break;
		}
	} else if (type == TYPE_OP3) {
		switch (opcode) {
		case OP_STS:
		case OP_LDS:
		default:
			break;
		}
	} else if (type == TYPE_OP4) {
		switch (opcode) {
		case OP_STP:
		case OP_LDP:
		default:
			break;
		}
	} else if (type == TYPE_OP5) {
		switch (opcode) {
		case OP_BR:
			op->jump = f->IMM11;
			break;
		case OP_BSR:
		case OP_PFXIO:
		case OP_PFX:
		default:
			break;
		}
	} else if (type == TYPE_OP8) {
		switch (opcode) {
		case OP_SAVE:
		case OP_TRAP:
		default:
			break;
		}
	} else if (type == TYPE_OP9) {
		switch (opcode) {
		case OP_EXT8S:
		case OP_EXT16S:
		case OP_ST8S:
		case OP_ST16S:
		default:
			break;
		}
	} else if (type == TYPE_OP11) {
		switch (opcode) {
		case OP_NOT:
		case OP_NEG:
		case OP_ABS:
		case OP_SEXT8:
		case OP_SEXT16:
		case OP_RLC:
		case OP_RRC:
		case OP_TRET:
		case OP_RESTORE:
		case OP_ST8D:
		case OP_ST16D:
		case OP_FILL8:
		case OP_FILL16:
		case OP_SKPRZ:
		case OP_SKPS:
		case OP_WRCTL:
		case OP_RDCTL:
		case OP_SKPRNZ:
		case OP_JMP:
		case OP_CALL:
		case OP_SWAP:
		case OP_USR1:
		case OP_USR2:
		case OP_USR3:
		case OP_USR4:
		case OP_MSTEP:
		case OP_MUL:
		default:
			break;
		}
	}
}

static int nios_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (!op) {
		return -1;
	}

	memset(op, 0, sizeof (RAnalOp));

	op->size = CGEN_MAX_INSN_SIZE;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (a->bits == 16) {
		nios_ops = nios16_ops;
	} else if (a->bits == 32) {
		nios_ops = nios32_ops;
	}

	ut16 insn;
	insn = r_read_ble16(buf, a->big_endian);

	struct insn_fields fields = { 0 };

	int opcode;
	opcode = parse_insn(a->bits, insn, &fields);

	if (opcode >= 0) {
		op->type = nios_ops[opcode].type;
	} else {
		return -1;
	}

	enum insn_type type = nios_ops[opcode].type_op;

	if (a->bits == 16) {
		nios16_anal(op, opcode, type, &fields);
	} else if (a->bits == 32) {
		nios32_anal(op, opcode, type, &fields);
	}

	return op->size;
}

static int set_reg_profile(RAnal *a) {
	if (a->bits == 16) {
		const char *p = \
			"=SR  ctl0\n"
			"=PC	pc\n"
			"=SP   r14\n"
			"=LR   r15\n"
			"=BP   r30\n"
			/* control registers */
			"gpr  ctl0      .16       0     0\n"
			"gpr  ctl1      .16       2     0\n"
			"gpr  ctl2      .16       4     0\n"
                        "gpr  ctl3      .16       6     0\n"
                        "gpr  ctl4      .16       8     0\n"
			"gpr  ctl5      .16      10     0\n"
			"gpr  ctl6      .16      12     0\n"
			"gpr  ctl7      .16      14     0\n"
			"gpr  ctl8      .16      16     0\n"
			"gpr  ctl9      .16      18     0\n"
			"gpr    pc      .16      20     0\n"
			"gpr     k      .11      22     0\n"
			/* r0-r7 are global (g0-g7) */
			"gpr    r0      .16      24     0\n"
			"gpr    r1      .16      26     0\n"
			"gpr    r2      .16      28     0\n"
			"gpr    r3      .16      30     0\n"
			"gpr    r4      .16      32     0\n"
			"gpr    r5      .16      34     0\n"
			"gpr    r6      .16      36     0\n"
			"gpr    r7      .16      38     0\n"
			/* r8-15 are out (o0-o7) */
			"gpr    r8      .16      40     0\n"
			"gpr    r9      .16      42     0\n"
			"gpr    r10     .16      44     0\n"
			"gpr    r11     .16      46     0\n"
			"gpr    r12     .16      48     0\n"
			"gpr    r13     .16      50     0\n"
			"gpr    r14     .16      52     0\n"
			"gpr    r15     .16      54     0\n"
			/* r16-23 are local (L0-L7) */
			"gpr    r16     .16      56     0\n"
			"gpr    r17     .16      58     0\n"
			"gpr    r18     .16      60     0\n"
			"gpr    r19     .16      62     0\n"
			"gpr    r20     .16      64     0\n"
			"gpr    r21     .16      66     0\n"
			"gpr    r22     .16      68     0\n"
			"gpr    r23     .16      70     0\n"
			/* r24-31 are in (i0-i7) */
			"gpr    r24     .16      72     0\n"
			"gpr    r25     .16      74     0\n"
			"gpr    r26     .16      76     0\n"
			"gpr    r27     .16      78     0\n"
			"gpr    r28     .16      80     0\n"
			"gpr    r29     .16      82     0\n"
			"gpr    r30     .16      84     0\n"
			"gpr    r31     .16      86     0\n";
		return r_reg_set_profile_string(a->reg, p);
	} else {
		const char *p = \
			"=SR  ctl0\n"
			"=PC	pc\n"
			"=SP   r14\n"
			"=LR   r15\n"
			"=BP   r30\n"
			/* control registers */
			"gpr  ctl0      .32       0     0\n"
			"gpr  ctl1      .32       4     0\n"
			"gpr  ctl2      .32       8     0\n"
                        "gpr  ctl3      .32      12     0\n"
                        "gpr  ctl4      .32      16     0\n"
			"gpr  ctl5      .32      20     0\n"
			"gpr  ctl6      .32      24     0\n"
			"gpr  ctl7      .32      28     0\n"
			"gpr  ctl8      .32      32     0\n"
			"gpr  ctl9      .32      36     0\n"
			"gpr    pc      .32      40     0\n"
			"gpr     k      .11      44     0\n"
			/* r0-r7 are global (g0-g7) */
			"gpr    r0      .32      48     0\n"
			"gpr    r1      .32      52     0\n"
			"gpr    r2      .32      56     0\n"
			"gpr    r3      .32      60     0\n"
			"gpr    r4      .32      64     0\n"
			"gpr    r5      .32      68     0\n"
			"gpr    r6      .32      72     0\n"
			"gpr    r7      .32      76     0\n"
			/* r8-15 are out (o0-o7) */
			"gpr    r8      .32      80     0\n"
			"gpr    r9      .32      84     0\n"
			"gpr    r10     .32      88     0\n"
			"gpr    r11     .32      92     0\n"
			"gpr    r12     .32      96     0\n"
			"gpr    r13     .32     100     0\n"
			"gpr    r14     .32     104     0\n"
			"gpr    r15     .32     108     0\n"
			/* r16-23 are local (L0-L7) */
			"gpr    r16     .32     112     0\n"
			"gpr    r17     .32     116     0\n"
			"gpr    r18     .32     120     0\n"
			"gpr    r19     .32     124     0\n"
			"gpr    r20     .32     128     0\n"
			"gpr    r21     .32     132     0\n"
			"gpr    r22     .32     136     0\n"
			"gpr    r23     .32     140     0\n"
			/* r24-31 are in (i0-i7) */
			"gpr    r24     .32     144     0\n"
			"gpr    r25     .32     148     0\n"
			"gpr    r26     .32     152     0\n"
			"gpr    r27     .32     156     0\n"
			"gpr    r28     .32     160     0\n"
			"gpr    r29     .32     164     0\n"
			"gpr    r30     .32     168     0\n"
			"gpr    r31     .32     172     0\n";
		return r_reg_set_profile_string(a->reg, p);
	}
}

RAnalPlugin r_anal_plugin_nios = {
	.name = "nios",
	.desc = "Altera Nios code analysis plugin",
	.license = "LGPL3",
	.arch = "nios",
	.bits = 16 | 32,
	.op = &nios_op,
	.set_reg_profile = &set_reg_profile,
	.init = NULL,
	.fini = NULL,
	.esil = false,
	.cmd_ext = NULL
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_nios,
	.version = R2_VERSION
};
#endif

