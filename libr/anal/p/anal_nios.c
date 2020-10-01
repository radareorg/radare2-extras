/* nios plugin by hewittc at 2018-2020 */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <sdb.h>

#include "dis-asm.h"

#include "nios/gnu/nios-desc.h"

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
	TYPE_OP6,
	TYPE_OP9,
	TYPE_OP8,
	TYPE_OP11,
	TYPE_OP5,
	TYPE_OP4,
	TYPE_OP3,
	TYPE_OPS
};

struct insn_fields {
	ut16 op11  : 11;
	ut16 op9   :  9;
	ut16 op8   :  8;
	ut16 op6   :  6;
	ut16 op5w  :  5;
	ut16 op5   :  5;
	ut16 op4   :  4;
	ut16 op3u  :  3;
	ut16 op3   :  3;
	ut16 op2v  :  2;

	st16 IMM11 : 11;
	st16 IMM10 : 10;
	st16 IMM9  :  9;
	st16 IMM8v :  8;
	st16 IMM8  :  8;
	st16 IMM6v :  6;
	st16 IMM6  :  6;
	st16 IMM5  :  5;
	st16 IMM4w :  4;
	st16 IMM4  :  4;
	st16 IMM2u :  2;
	st16 IMM1u :  1;

	st16 P     :  2;
	st16 B     :  5;
	st16 A     :  5;
};

struct insn_op {
	enum mach_attr mach;
	enum insn_type type;
	ut16 opcode;
	enum insn_format format;
	_RAnalOpType r_op_type;
};

#define INSN_OPS_MAX 131
static const struct insn_op insn_ops[INSN_OPS_MAX] = {
	{ MACH_NIOS16, TYPE_OP6,  OP_ADD,     FMT_RR,   R_ANAL_OP_TYPE_ADD },
	{ MACH_NIOS16, TYPE_OP6,  OP_ADDI,    FMT_Ri5,  R_ANAL_OP_TYPE_ADD },
	{ MACH_NIOS16, TYPE_OP6,  OP_SUB,     FMT_RR,   R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS16, TYPE_OP6,  OP_SUBI,    FMT_Ri5,  R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS16, TYPE_OP6,  OP_CMP,     FMT_RR,   R_ANAL_OP_TYPE_CMP },
	{ MACH_NIOS16, TYPE_OP6,  OP_CMPI,    FMT_Ri5,  R_ANAL_OP_TYPE_CMP },
	{ MACH_NIOS16, TYPE_OP6,  OP_LSL,     FMT_RR,   R_ANAL_OP_TYPE_SHL },
	{ MACH_NIOS16, TYPE_OP6,  OP_LSLI,    FMT_Ri4,  R_ANAL_OP_TYPE_SHL },
	{ MACH_NIOS16, TYPE_OP6,  OP_LSR,     FMT_RR,   R_ANAL_OP_TYPE_SHR },
	{ MACH_NIOS16, TYPE_OP6,  OP_LSRI,    FMT_Ri4,  R_ANAL_OP_TYPE_SHR },
	{ MACH_NIOS16, TYPE_OP6,  OP_ASR,     FMT_RR,   R_ANAL_OP_TYPE_SAR },
	{ MACH_NIOS16, TYPE_OP6,  OP_ASRI,    FMT_Ri4,  R_ANAL_OP_TYPE_SAR },
	{ MACH_NIOS16, TYPE_OP6,  OP_MOV,     FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP6,  OP_MOVI,    FMT_Ri5,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP6,  OP_AND,     FMT_RR,   R_ANAL_OP_TYPE_AND },
	{ MACH_NIOS16, TYPE_OP6,  OP_ANDN,    FMT_RR,   R_ANAL_OP_TYPE_AND },
	{ MACH_NIOS16, TYPE_OP6,  OP_OR,      FMT_RR,   R_ANAL_OP_TYPE_OR },
	{ MACH_NIOS16, TYPE_OP6,  OP_XOR,     FMT_RR,   R_ANAL_OP_TYPE_XOR },
	{ MACH_NIOS16, TYPE_OP6,  OP_BGEN,    FMT_Ri4,  R_ANAL_OP_TYPE_MUL },
	{ MACH_NIOS16, TYPE_OP6,  OP_EXT8D,   FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP6,  OP_SKP0,    FMT_Ri4,  R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS16, TYPE_OP6,  OP_SKP1,    FMT_Ri4,  R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS16, TYPE_OP6,  OP_LD,      FMT_RR,   R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS16, TYPE_OP6,  OP_ST,      FMT_RR,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP6,  OP_STS8S,   FMT_i10,  R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP6,  OP_ADDC,    FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP6,  OP_SUBC,    FMT_Ri5,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP6,  OP_USR0,    FMT_RR,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS16, TYPE_OP3,  OP_STS,     FMT_Ri8,  R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP3,  OP_LDS,     FMT_Ri8,  R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS16, TYPE_OP4,  OP_STP,     FMT_RPi5, R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP4,  OP_LDP,     FMT_RPi5, R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS16, TYPE_OP5,  OP_BR,      FMT_i11,  R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS16, TYPE_OP5,  OP_BSR,     FMT_i11,  R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS16, TYPE_OP5,  OP_PFX,     FMT_i11,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP8,  OP_SAVE,    FMT_i8v,  R_ANAL_OP_TYPE_PUSH },
	{ MACH_NIOS16, TYPE_OP8,  OP_TRAP,    FMT_i6v,  R_ANAL_OP_TYPE_TRAP },
	{ MACH_NIOS16, TYPE_OP9,  OP_EXT8S,   FMT_Ri1u, R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP9,  OP_ST8S,    FMT_Ri1u, R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP11, OP_NOT,     FMT_Rw,   R_ANAL_OP_TYPE_NOT },
	{ MACH_NIOS16, TYPE_OP11, OP_NEG,     FMT_Rw,   R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS16, TYPE_OP11, OP_ABS,     FMT_Rw,   R_ANAL_OP_TYPE_ABS },
	{ MACH_NIOS16, TYPE_OP11, OP_SEXT8,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP11, OP_RLC,     FMT_Rw,   R_ANAL_OP_TYPE_ROL },
	{ MACH_NIOS16, TYPE_OP11, OP_RRC,     FMT_Rw,   R_ANAL_OP_TYPE_ROR },
	{ MACH_NIOS16, TYPE_OP11, OP_TRET,    FMT_Rw,   R_ANAL_OP_TYPE_UJMP },
	{ MACH_NIOS16, TYPE_OP11, OP_RESTORE, FMT_w,    R_ANAL_OP_TYPE_POP },
	{ MACH_NIOS16, TYPE_OP11, OP_ST8D,    FMT_Rw,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS16, TYPE_OP11, OP_FILL8,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP11, OP_SKPRZ,   FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS16, TYPE_OP11, OP_SKPS,    FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS16, TYPE_OP11, OP_WRCTL,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP11, OP_RDCTL,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP11, OP_SKPRNZ,  FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS16, TYPE_OP11, OP_JMP,     FMT_Rw,   R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS16, TYPE_OP11, OP_CALL,    FMT_Rw,   R_ANAL_OP_TYPE_CALL },
	{ MACH_NIOS16, TYPE_OP11, OP_SWAP,    FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS16, TYPE_OP11, OP_USR1,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS16, TYPE_OP11, OP_USR2,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS16, TYPE_OP11, OP_USR3,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS16, TYPE_OP11, OP_USR4,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP6,  OP_ADD,     FMT_RR,   R_ANAL_OP_TYPE_ADD },
	{ MACH_NIOS32, TYPE_OP6,  OP_ADDI,    FMT_Ri5,  R_ANAL_OP_TYPE_ADD },
	{ MACH_NIOS32, TYPE_OP6,  OP_SUB,     FMT_RR,   R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS32, TYPE_OP6,  OP_SUBI,    FMT_Ri5,  R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS32, TYPE_OP6,  OP_CMP,     FMT_RR,   R_ANAL_OP_TYPE_CMP },
	{ MACH_NIOS32, TYPE_OP6,  OP_CMPI,    FMT_Ri5,  R_ANAL_OP_TYPE_CMP },
	{ MACH_NIOS32, TYPE_OP6,  OP_LSL,     FMT_RR,   R_ANAL_OP_TYPE_SHL },
	{ MACH_NIOS32, TYPE_OP6,  OP_LSLI,    FMT_Ri5,  R_ANAL_OP_TYPE_SHL },
	{ MACH_NIOS32, TYPE_OP6,  OP_LSR,     FMT_RR,   R_ANAL_OP_TYPE_SHR },
	{ MACH_NIOS32, TYPE_OP6,  OP_LSRI,    FMT_Ri5,  R_ANAL_OP_TYPE_SHR },
	{ MACH_NIOS32, TYPE_OP6,  OP_ASR,     FMT_RR,   R_ANAL_OP_TYPE_SAR },
	{ MACH_NIOS32, TYPE_OP6,  OP_ASRI,    FMT_Ri5,  R_ANAL_OP_TYPE_SAR },
	{ MACH_NIOS32, TYPE_OP6,  OP_MOV,     FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP6,  OP_MOVI,    FMT_Ri5,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP6,  OP_AND,     FMT_RR,   R_ANAL_OP_TYPE_AND },
	{ MACH_NIOS32, TYPE_OP6,  OP_ANDN,    FMT_RR,   R_ANAL_OP_TYPE_AND },
	{ MACH_NIOS32, TYPE_OP6,  OP_OR,      FMT_RR,   R_ANAL_OP_TYPE_OR },
	{ MACH_NIOS32, TYPE_OP6,  OP_XOR,     FMT_RR,   R_ANAL_OP_TYPE_XOR },
	{ MACH_NIOS32, TYPE_OP6,  OP_BGEN,    FMT_Ri5,  R_ANAL_OP_TYPE_MUL },
	{ MACH_NIOS32, TYPE_OP6,  OP_EXT8D,   FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP6,  OP_SKP0,    FMT_Ri5,  R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS32, TYPE_OP6,  OP_SKP1,    FMT_Ri5,  R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS32, TYPE_OP6,  OP_LD,      FMT_RR,   R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS32, TYPE_OP6,  OP_ST,      FMT_RR,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP6,  OP_STS8S,   FMT_i10,  R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP6,  OP_STS16S,  FMT_i9,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP6,  OP_EXT16D,  FMT_RR,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP6,  OP_MOVHI,   FMT_Ri5,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP6,  OP_USR0,    FMT_RR,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP3,  OP_STS,     FMT_Ri8,  R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP3,  OP_LDS,     FMT_Ri8,  R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS32, TYPE_OP4,  OP_STP,     FMT_RPi5, R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP4,  OP_LDP,     FMT_RPi5, R_ANAL_OP_TYPE_LOAD },
	{ MACH_NIOS32, TYPE_OP5,  OP_BR,      FMT_i11,  R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS32, TYPE_OP5,  OP_BSR,     FMT_i11,  R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS32, TYPE_OP5,  OP_PFXIO,   FMT_i11,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP5,  OP_PFX,     FMT_i11,  R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP8,  OP_SAVE,    FMT_i8v,  R_ANAL_OP_TYPE_PUSH },
	{ MACH_NIOS32, TYPE_OP8,  OP_TRAP,    FMT_i6v,  R_ANAL_OP_TYPE_TRAP },
	{ MACH_NIOS32, TYPE_OP9,  OP_EXT8S,   FMT_Ri1u, R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP9,  OP_EXT16S,  FMT_Ri1u, R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP9,  OP_ST8S,    FMT_Ri1u, R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP9,  OP_ST16S,   FMT_Ri1u, R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP11, OP_NOT,     FMT_Rw,   R_ANAL_OP_TYPE_NOT },
	{ MACH_NIOS32, TYPE_OP11, OP_NEG,     FMT_Rw,   R_ANAL_OP_TYPE_SUB },
	{ MACH_NIOS32, TYPE_OP11, OP_ABS,     FMT_Rw,   R_ANAL_OP_TYPE_ABS },
	{ MACH_NIOS32, TYPE_OP11, OP_SEXT8,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_SEXT16,  FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_RLC,     FMT_Rw,   R_ANAL_OP_TYPE_ROL },
	{ MACH_NIOS32, TYPE_OP11, OP_RRC,     FMT_Rw,   R_ANAL_OP_TYPE_ROR },
	{ MACH_NIOS32, TYPE_OP11, OP_TRET,    FMT_Rw,   R_ANAL_OP_TYPE_UJMP },
	{ MACH_NIOS32, TYPE_OP11, OP_RESTORE, FMT_w,    R_ANAL_OP_TYPE_POP },
	{ MACH_NIOS32, TYPE_OP11, OP_ST8D,    FMT_Rw,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP11, OP_ST16D,   FMT_Rw,   R_ANAL_OP_TYPE_STORE },
	{ MACH_NIOS32, TYPE_OP11, OP_FILL8,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_FILL16,  FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_SKPRZ,   FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS32, TYPE_OP11, OP_SKPS,    FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS32, TYPE_OP11, OP_WRCTL,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_RDCTL,   FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_SKPRNZ,  FMT_Rw,   R_ANAL_OP_TYPE_CJMP },
	{ MACH_NIOS32, TYPE_OP11, OP_JMP,     FMT_Rw,   R_ANAL_OP_TYPE_JMP },
	{ MACH_NIOS32, TYPE_OP11, OP_CALL,    FMT_Rw,   R_ANAL_OP_TYPE_CALL },
	{ MACH_NIOS32, TYPE_OP11, OP_SWAP,    FMT_Rw,   R_ANAL_OP_TYPE_MOV },
	{ MACH_NIOS32, TYPE_OP11, OP_USR1,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP11, OP_USR2,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP11, OP_USR3,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP11, OP_USR4,    FMT_Rw,   R_ANAL_OP_TYPE_IO },
	{ MACH_NIOS32, TYPE_OP11, OP_MSTEP,   FMT_Rw,   R_ANAL_OP_TYPE_MUL },
	{ MACH_NIOS32, TYPE_OP11, OP_MUL,     FMT_Rw,   R_ANAL_OP_TYPE_MUL }
};

struct nios_info {
	HtPP *ops;
};

static struct nios_info *nios;

static const char *nios16_reg_profile = \
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
	"gpr     k      .16      22     0\n"
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
	/* r16-23 are local (l0-l7) */
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

static const char *nios32_reg_profile = \
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
	"gpr     k      .16      44     0\n"
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
	/* r16-23 are local (l0-l7) */
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

static int parse_insn(enum mach_attr mach, ut16 insn, struct insn_op **op, struct insn_fields *f) {
	ut16 insns[TYPE_OPS] = {
		f_op6(insn),
		f_op9(insn),
		f_op8(insn),
		f_op11(insn),
		f_op5(insn),
		f_op4(insn),
		f_op3(insn),
	};

	bool found;
	int opcode;

	for (int type = TYPE_OP6; type < TYPE_OPS; type++) {
		const char *key = sdb_fmt("%d %d %d", mach, type, insns[type]);
		*op = ht_pp_find(nios->ops, key, &found);

		if (found) {
			opcode = (*op)->opcode;
			break;
		}
	}

	if (!found) {
		return -1;
	}

	switch ((*op)->format) {
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
	default:
		break;
	}

	return opcode;
}

static void nios16_anal(RAnalOp *op, ut16 opcode, enum insn_type type, struct insn_fields *f) {
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
			op->jump = op->addr + ((f->IMM11 + 1) * 2);
			break;
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

static void nios32_anal(RAnalOp *op, ut16 opcode, enum insn_type type, struct insn_fields *f) {
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
		case OP_BSR:
			op->jump = op->addr + ((f->IMM11 + 1) * 2);
			break;
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

static int nios_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	if (!op) {
		return -1;
	}

	memset(op, 0, sizeof (RAnalOp));

	op->size = CGEN_MAX_INSN_SIZE;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	enum mach_attr arch;
	void (*nios_anal)(RAnalOp *, ut16, enum insn_type, struct insn_fields *);

	if (a->bits == 16) {
		arch = MACH_NIOS16;
		nios_anal = &nios16_anal;
	} else {
		arch = MACH_NIOS32;
		nios_anal = &nios32_anal;
	}

	ut16 insn;
	insn = r_read_ble16(data, a->big_endian);

	struct insn_op *insn_op;
	struct insn_fields insn_fields = { 0 };

	int opcode;
	opcode = parse_insn(arch, insn, &insn_op, &insn_fields);

	if (opcode >= 0) {
		op->type = insn_op->r_op_type;
		(*nios_anal)(op, opcode, insn_op->type, &insn_fields);
	}

	return op->size;
}

static bool set_reg_profile(RAnal *a) {
	const char *nios_reg_profile;

	if (a->bits == 16) {
		nios_reg_profile = nios16_reg_profile;
	} else {
		nios_reg_profile = nios32_reg_profile;
	}

	return r_reg_set_profile_string(a->reg, nios_reg_profile);
}

static void nios_free_kv(HtPPKv *kv) {
	if (kv && kv->key) {
		free(kv->key);
	}
}

static int nios_init(void *user) {
	if (!nios) {
		nios = calloc(1, sizeof (*nios));
		nios->ops = ht_pp_new(NULL, nios_free_kv, NULL);
		if (!nios->ops) {
			return -1;
		}
	}

	for (int i = 0; i < INSN_OPS_MAX; i++) {
		const struct insn_op *op = &insn_ops[i];
		const char *key = sdb_fmt("%d %d %d", op->mach, op->type, op->opcode);
		ht_pp_insert(nios->ops, key, (void *) op);
	}

	return 0;
}

static int nios_fini(void *user) {
	if (nios && nios->ops) {
		ht_pp_free(nios->ops);
	}

	if (nios) {
		free(nios);
	}

	return 0;
}

RAnalPlugin r_anal_plugin_nios = {
	.name = "nios",
	.desc = "Altera Nios code analysis plugin",
	.license = "LGPL3",
	.arch = "nios",
	.bits = 16 | 32,
	.esil = false,
	.init = &nios_init,
	.fini = &nios_fini,
	.op = &nios_op,
	.cmd_ext = NULL,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_nios,
	.version = R2_VERSION
};
#endif

