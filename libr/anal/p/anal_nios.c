#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "dis-asm.h"

#include "nios/gnu/nios-desc.h"

#define f_op11(i)   (i >> 5)
#define f_op9(i)    (i >> 7)
#define f_op8(i)    (i >> 8)
#define f_op6(i)    (i >> 10)
#define f_op5w(i)   (i >> 5) & 0x001f
#define f_op5(i)    (i >> 11)
#define f_op4(i)    (i >> 12)
#define f_op3u(i)   (i >> 7) & 0x0007
#define f_op3(i)    (i >> 13)
#define f_op2v(i)   (i >> 8) & 0x0003

#define f_IMM11(i)  (i >> 0) & 0x07ff
#define f_IMM10(i)  (i >> 0) & 0x03ff
#define f_IMM9(i)   (i >> 1) & 0x01ff
#define f_IMM8v(i)  (i >> 0) & 0x00ff
#define f_IMM8(i)   (i >> 5) & 0x00ff
#define f_IMM6v(i)  (i >> 0) & 0x003f
#define f_IMM6(i)   (i >> 5) & 0x003f
#define f_IMM5(i)   (i >> 5) & 0x001f
#define f_IMM4w(i)  (i >> 0) & 0x00ff
#define f_IMM4(i)   (i >> 5) & 0x000f
#define f_IMM2u(i)  (i >> 5) & 0x0003
#define f_IMM1u(i)  (i >> 6) & 0x0001

#define f_P(i)      (i >> 10) & 0x0003
#define f_B(i)      (i >> 5) & 0x001f
#define f_A(i)      (i >> 0) & 0x001f

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

struct insn_operands {
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
	enum insn_format format;
};

static struct nios_op nios16_ops[] __attribute__((unused)) = {
	// op6
	[OP_ADD]     = { R_ANAL_OP_TYPE_ADD,   FMT_RR },
	[OP_ADDI]    = { R_ANAL_OP_TYPE_ADD,   FMT_Ri5 },
	[OP_SUB]     = { R_ANAL_OP_TYPE_SUB,   FMT_RR },
	[OP_SUBI]    = { R_ANAL_OP_TYPE_SUB,   FMT_Ri5 },
	[OP_CMP]     = { R_ANAL_OP_TYPE_CMP,   FMT_RR },
	[OP_CMPI]    = { R_ANAL_OP_TYPE_CMP,   FMT_Ri5 },
	[OP_LSL]     = { R_ANAL_OP_TYPE_SHL,   FMT_RR },
	[OP_LSLI]    = { R_ANAL_OP_TYPE_SHL,   FMT_Ri4 },
	[OP_LSR]     = { R_ANAL_OP_TYPE_SHR,   FMT_RR },
	[OP_LSRI]    = { R_ANAL_OP_TYPE_SHR,   FMT_Ri4 },
	[OP_ASR]     = { R_ANAL_OP_TYPE_SAR,   FMT_RR },
	[OP_ASRI]    = { R_ANAL_OP_TYPE_SAR,   FMT_Ri4 },
	[OP_MOV]     = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_MOVI]    = { R_ANAL_OP_TYPE_MOV,   FMT_Ri5 },
	[OP_AND]     = { R_ANAL_OP_TYPE_AND,   FMT_RR },
	[OP_ANDN]    = { R_ANAL_OP_TYPE_AND,   FMT_RR },
	[OP_OR]      = { R_ANAL_OP_TYPE_OR,    FMT_RR },
	[OP_XOR]     = { R_ANAL_OP_TYPE_XOR,   FMT_RR },
	[OP_BGEN]    = { R_ANAL_OP_TYPE_MUL,   FMT_Ri4 },
	[OP_EXT8D]   = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_SKP0]    = { R_ANAL_OP_TYPE_CJMP,  FMT_Ri4 },
	[OP_SKP1]    = { R_ANAL_OP_TYPE_CJMP,  FMT_Ri4 },
	[OP_LD]      = { R_ANAL_OP_TYPE_LOAD,  FMT_RR },
	[OP_ST]      = { R_ANAL_OP_TYPE_STORE, FMT_RR },
	[OP_STS8S]   = { R_ANAL_OP_TYPE_STORE, FMT_i10 },
	[OP_ADDC]    = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_SUBC]    = { R_ANAL_OP_TYPE_MOV,   FMT_Ri5 },
	[OP_USR0]    = { R_ANAL_OP_TYPE_IO,    FMT_RR },

	// op3
	[OP_STS]     = { R_ANAL_OP_TYPE_STORE, FMT_Ri8 },
	[OP_LDS]     = { R_ANAL_OP_TYPE_LOAD,  FMT_Ri8 },

	// op4
	[OP_STP]     = { R_ANAL_OP_TYPE_STORE, FMT_RPi5 },
	[OP_LDP]     = { R_ANAL_OP_TYPE_LOAD,  FMT_RPi5 },

	// op5
	[OP_BR]      = { R_ANAL_OP_TYPE_JMP,   FMT_i11 },
	[OP_BSR]     = { R_ANAL_OP_TYPE_JMP,   FMT_i11 },
	[OP_PFX]     = { R_ANAL_OP_TYPE_MOV,   FMT_i11 },

	// op8
	[OP_SAVE]    = { R_ANAL_OP_TYPE_PUSH,  FMT_i8v },
	[OP_TRAP]    = { R_ANAL_OP_TYPE_TRAP,  FMT_i6v },

	// op9
	[OP_EXT8S]   = { R_ANAL_OP_TYPE_MOV,   FMT_Ri1u },
	[OP_ST8S]    = { R_ANAL_OP_TYPE_STORE, FMT_Ri1u },

	// op11
	[OP_NOT]     = { R_ANAL_OP_TYPE_NOT,   FMT_Rw },
	[OP_NEG]     = { R_ANAL_OP_TYPE_SUB,   FMT_Rw },
	[OP_ABS]     = { R_ANAL_OP_TYPE_ABS,   FMT_Rw },
	[OP_SEXT8]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_RLC]     = { R_ANAL_OP_TYPE_ROL,   FMT_Rw },
	[OP_RRC]     = { R_ANAL_OP_TYPE_ROR,   FMT_Rw },
	[OP_TRET]    = { R_ANAL_OP_TYPE_UJMP,  FMT_Rw },
	[OP_RESTORE] = { R_ANAL_OP_TYPE_POP,   FMT_w },
	[OP_ST8D]    = { R_ANAL_OP_TYPE_STORE, FMT_Rw },
	[OP_FILL8]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_SKPRZ]   = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_SKPS]    = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_WRCTL]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_RDCTL]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_SKPRNZ]  = { R_ANAL_OP_TYPE_CJMP,  FMT_Rw },
	[OP_JMP]     = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_CALL]    = { R_ANAL_OP_TYPE_CALL,  FMT_Rw },
	[OP_SWAP]    = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_USR1]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR2]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR3]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR4]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
};

static struct nios_op nios32_ops[] = {
	// op6
	[OP_ADD]     = { R_ANAL_OP_TYPE_ADD,   FMT_RR },
	[OP_ADDI]    = { R_ANAL_OP_TYPE_ADD,   FMT_Ri5 },
	[OP_SUB]     = { R_ANAL_OP_TYPE_SUB,   FMT_RR },
	[OP_SUBI]    = { R_ANAL_OP_TYPE_SUB,   FMT_Ri5 },
	[OP_CMP]     = { R_ANAL_OP_TYPE_CMP,   FMT_RR },
	[OP_CMPI]    = { R_ANAL_OP_TYPE_CMP,   FMT_Ri5 },
	[OP_LSL]     = { R_ANAL_OP_TYPE_SHL,   FMT_RR },
	[OP_LSLI]    = { R_ANAL_OP_TYPE_SHL,   FMT_Ri5 },
	[OP_LSR]     = { R_ANAL_OP_TYPE_SHR,   FMT_RR },
	[OP_LSRI]    = { R_ANAL_OP_TYPE_SHR,   FMT_Ri5 },
	[OP_ASR]     = { R_ANAL_OP_TYPE_SAR,   FMT_RR },
	[OP_ASRI]    = { R_ANAL_OP_TYPE_SAR,   FMT_Ri5 },
	[OP_MOV]     = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_MOVI]    = { R_ANAL_OP_TYPE_MOV,   FMT_Ri5 },
	[OP_AND]     = { R_ANAL_OP_TYPE_AND,   FMT_RR },
	[OP_ANDN]    = { R_ANAL_OP_TYPE_AND,   FMT_RR },
	[OP_OR]      = { R_ANAL_OP_TYPE_OR,    FMT_RR },
	[OP_XOR]     = { R_ANAL_OP_TYPE_XOR,   FMT_RR },
	[OP_BGEN]    = { R_ANAL_OP_TYPE_MUL,   FMT_Ri5 },
	[OP_EXT8D]   = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_SKP0]    = { R_ANAL_OP_TYPE_CJMP,  FMT_Ri5 },
	[OP_SKP1]    = { R_ANAL_OP_TYPE_CJMP,  FMT_Ri5 },
	[OP_LD]      = { R_ANAL_OP_TYPE_LOAD,  FMT_RR },
	[OP_ST]      = { R_ANAL_OP_TYPE_STORE, FMT_RR },
	[OP_STS8S]   = { R_ANAL_OP_TYPE_STORE, FMT_i10 },
	[OP_STS16S]  = { R_ANAL_OP_TYPE_STORE, FMT_i9 },
	[OP_EXT16D]  = { R_ANAL_OP_TYPE_MOV,   FMT_RR },
	[OP_MOVHI]   = { R_ANAL_OP_TYPE_MOV,   FMT_Ri5 },
	[OP_USR0]    = { R_ANAL_OP_TYPE_IO,    FMT_RR },

	// op3
	[OP_STS]     = { R_ANAL_OP_TYPE_STORE, FMT_Ri8 },
	[OP_LDS]     = { R_ANAL_OP_TYPE_LOAD,  FMT_Ri8 },

	// op4
	[OP_STP]     = { R_ANAL_OP_TYPE_STORE, FMT_RPi5 },
	[OP_LDP]     = { R_ANAL_OP_TYPE_LOAD,  FMT_RPi5 },

	// op5
	[OP_BR]      = { R_ANAL_OP_TYPE_JMP,   FMT_i11 },
	[OP_BSR]     = { R_ANAL_OP_TYPE_JMP,   FMT_i11 },
	[OP_PFXIO]   = { R_ANAL_OP_TYPE_MOV,   FMT_i11 },
	[OP_PFX]     = { R_ANAL_OP_TYPE_MOV,   FMT_i11 },

	// op8
	[OP_SAVE]    = { R_ANAL_OP_TYPE_PUSH,  FMT_i8v },
	[OP_TRAP]    = { R_ANAL_OP_TYPE_TRAP,  FMT_i6v },

	// op9
	[OP_EXT8S]   = { R_ANAL_OP_TYPE_MOV,   FMT_Ri1u },
	[OP_EXT16S]  = { R_ANAL_OP_TYPE_MOV,   FMT_Ri1u },
	[OP_ST8S]    = { R_ANAL_OP_TYPE_STORE, FMT_Ri1u },
	[OP_ST16S]   = { R_ANAL_OP_TYPE_STORE, FMT_Ri1u },

	// op11
	[OP_NOT]     = { R_ANAL_OP_TYPE_NOT,   FMT_Rw },
	[OP_NEG]     = { R_ANAL_OP_TYPE_SUB,   FMT_Rw },
	[OP_ABS]     = { R_ANAL_OP_TYPE_ABS,   FMT_Rw },
	[OP_SEXT8]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_SEXT16]  = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_RLC]     = { R_ANAL_OP_TYPE_ROL,   FMT_Rw },
	[OP_RRC]     = { R_ANAL_OP_TYPE_ROR,   FMT_Rw },
	[OP_TRET]    = { R_ANAL_OP_TYPE_UJMP,  FMT_Rw },
	[OP_RESTORE] = { R_ANAL_OP_TYPE_POP,   FMT_w },
	[OP_ST8D]    = { R_ANAL_OP_TYPE_STORE, FMT_Rw },
	[OP_ST16D]   = { R_ANAL_OP_TYPE_STORE, FMT_Rw },
	[OP_FILL8]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_FILL16]  = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_LDM]     = { R_ANAL_OP_TYPE_LOAD,  FMT_Rw },
	[OP_STM]     = { R_ANAL_OP_TYPE_STORE, FMT_Rw },
	[OP_SKPRZ]   = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_SKPS]    = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_WRCTL]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_RDCTL]   = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_SKPRNZ]  = { R_ANAL_OP_TYPE_CJMP,  FMT_Rw },
	[OP_JMP]     = { R_ANAL_OP_TYPE_JMP,   FMT_Rw },
	[OP_CALL]    = { R_ANAL_OP_TYPE_CALL,  FMT_Rw },
	[OP_SWAP]    = { R_ANAL_OP_TYPE_MOV,   FMT_Rw },
	[OP_USR1]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR2]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR3]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_USR4]    = { R_ANAL_OP_TYPE_IO,    FMT_Rw },
	[OP_MSTEP]   = { R_ANAL_OP_TYPE_MUL,   FMT_Rw },
	[OP_MUL]     = { R_ANAL_OP_TYPE_MUL,   FMT_Rw }
};

static inline int valid_op6(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op6(insn)) {
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
	case OP_STS16S:
	case OP_ADDC: // nios32 OP_EXT16D
	case OP_SUBC: // nios32 OP_MOVHI
	case OP_USR0:
		opcode = f_op6(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op9(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op9(insn)) {
	case OP_EXT8S:
	case OP_EXT16S:
	case OP_ST8S:
	case OP_ST16S:
		opcode = f_op9(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op8(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op8(insn)) {
	case OP_SAVE:
	case OP_TRAP:
	case OP_JMPC:
	case OP_CALLC:
		opcode = f_op8(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op11(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op11(insn)) {
	case OP_NOT:
	case OP_NEG:
	case OP_ABS:
	case OP_SEXT8:
	case OP_SEXT16:
	case OP_RLC:
	case OP_RRC:
	case OP_SWAP:
	case OP_USR1:
	case OP_USR2:
	case OP_USR3:
	case OP_USR4:
	case OP_RESTORE:
	case OP_TRET:
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
	case OP_MSTEP:
	case OP_MUL:
		opcode = f_op11(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op5(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op5(insn)) {
	case OP_BR:
	case OP_BSR:
	case OP_PFXIO:
	case OP_PFX:
		opcode = f_op5(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op4(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op4(insn)) {
	case OP_STP:
	case OP_LDP:
		opcode = f_op4(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static inline int valid_op3(ut16 insn) {
	int opcode;
	opcode = -1;

	switch (f_op3(insn)) {
	case OP_STS:
	case OP_LDS:
		opcode = f_op3(insn);
		break;
	default:
		break;
	}

	return opcode;
}

static int parse_insn(ut16 insn, struct insn_operands *o) {
	int (*valid_op[6])(ut16) = {
		valid_op6,
		valid_op9,
		valid_op11,
		valid_op5,
		valid_op4,
		valid_op3
	};

	int opcode;

	for (int i = 0; i < 6; i++) {
		opcode = valid_op[i](insn);

		if (opcode >= 0) {
			break;
		}
	}

	if (opcode < 0) {
		return opcode;
	}

	switch (nios32_ops[opcode].format) {
	case FMT_RR:
		o->op6 = f_op6(insn);
		o->B = f_B(insn);
		o->A = f_A(insn);
		break;

	case FMT_Ri5:
		o->op6 = f_op6(insn);
		o->IMM5 = f_IMM5(insn);
		o->A = f_A(insn);
		break;

	case FMT_Ri4:
		o->op6 = f_op6(insn);
		o->IMM4 = f_IMM4(insn);
		o->A = f_A(insn);
		break;

	case FMT_RPi5:
		o->op4 = f_op4(insn);
		o->P = f_P(insn);
		o->B = f_B(insn);
		o->A = f_A(insn);
		break;
		
	case FMT_Ri6:
		o->op5 = f_op5(insn);
		o->IMM6 = f_IMM6(insn);
		o->A = f_A(insn);
		break;
		
	case FMT_Ri8:
		o->op3 = f_op3(insn);
		o->IMM8 = f_IMM8(insn);
		o->A = f_A(insn);
		break;

	case FMT_i9:
		o->op6 = f_op6(insn);
		o->IMM9 = f_IMM9(insn);
		break;

	case FMT_i10:
		o->op6 = f_op6(insn);
		o->IMM10 = f_IMM10(insn);
		break;

	case FMT_i11:
		o->op5 = f_op5(insn);
		o->IMM11 = f_IMM11(insn);
		break;

	case FMT_Ri1u:
		o->op6 = f_op6(insn);
		o->op3u = f_op3u(insn);
		o->IMM1u = f_IMM1u(insn);
		o->A = f_A(insn);
		break;

	case FMT_Ri2u:
		o->op6 = f_op6(insn);
		o->op3u = f_op3u(insn);
		o->IMM2u = f_IMM2u(insn);
		o->A = f_A(insn);
		break;

	case FMT_i8v:
		o->op6 = f_op6(insn);
		o->op2v = f_op2v(insn);
		o->IMM8v = f_IMM8v(insn);
		break;

	case FMT_i6v:
		o->op6 = f_op6(insn);
		o->op2v = f_op2v(insn);
		o->IMM6v = f_IMM6v(insn);
		break;

	case FMT_Rw:
		o->op6 = f_op6(insn);
		o->op5w = f_op5w(insn);
		o->A = f_A(insn);
		break;

	case FMT_i4w:
		o->op6 = f_op6(insn);
		o->op5w = f_op5w(insn);
		o->IMM4w = f_IMM4w(insn);
		break;

	case FMT_w:
		o->op6 = f_op6(insn);
		o->op5w = f_op5w(insn);
		break;

	case FMT_UNKNOWN:
	default:
		break;
	}

	return opcode;
}

static int nios_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (!op) {
		return 1;
	}

	memset(op, 0, sizeof(RAnalOp));

	op->size = CGEN_MAX_INSN_SIZE;
	op->type = R_ANAL_OP_TYPE_UNK;

	ut16 insn;
	insn = r_read_ble16(buf, a->big_endian);

	struct insn_operands operands = { 0 };

	int opcode;
	opcode = parse_insn(insn, &operands);

	if (opcode >= 0) {
		op->type = nios32_ops[opcode].type;
	}

	switch (op->type) {
	case R_ANAL_OP_TYPE_UNK:
	default:
		break;
	}

	return 2;
}

RAnalPlugin r_anal_plugin_nios = {
	.name = "nios",
	.desc = "Altera Nios code analysis plugin",
	.license = "LGPL3",
	.arch = "nios",
	.bits = 16 | 32,
	.op = nios_op,
	// .init = nios_anal_init,
	// .fini = nios_anal_fini,
	.esil = false,
	// .cmd_ext = nios_cmd_ext
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_nios,
	.version = R2_VERSION
};
#endif

