/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* MN10300 / AM33 instruction decoder, a port of the GNU binutils opcodes/m10300-dis.c
 * matching rules driven by the opcode table in mn103_opcodes.h. */

#ifndef MN103_DECODE_H
#define MN103_DECODE_H

#include <r_types.h>
#include <r_util/r_strbuf.h>
#include "mn103_opcodes.h"

#define MN103_MAX_OPS 6

typedef struct {
	ut8 index;          /* operand descriptor index (MN103_OP_*) */
	ut32 flags;         /* descriptor flags (MN103_OPERAND_*) */
	st32 value;         /* register number, immediate, pc-relative target, memory address or register-list mask */
	const char *reg;    /* register name for register-like operands, NULL otherwise */
} Mn103Operand;

typedef struct {
	int size;                   /* bytes consumed; the binutils length rule, also for an unknown opcode */
	const Mn103Opcode *desc;    /* matched row, NULL when unknown */
	int index;                  /* row index in mn103_opcodes, -1 when unknown */
	ut32 insn;                  /* the opcode word binutils matches against (up to 4 bytes, big-endian order) */
	int nops;
	Mn103Operand ops[MN103_MAX_OPS];
} Mn103Insn;

/* Length of the instruction starting with first byte b0 (the opcode-prefix rule; FE 8x is refined to 5 in decode). */
int mn103_insn_size(ut8 b0);

/* Decode one instruction. mach: MN103_MACH_BASE, MN103_MACH_AM30, MN103_MACH_AM33 or MN103_MACH_AM33_2;
 * rows of a lower machine level are accepted (AM33-2 is a superset). Returns false when the bytes do not
 * match any row or len is too short; in->size still carries the length rule when it is known. */
bool mn103_decode(Mn103Insn *in, const ut8 *buf, int len, ut64 addr, int mach);

/* Render the instruction in binutils syntax with hexadecimal numbers ("mov 0x10, d3", "mov d3, (0x8, a2)"). */
void mn103_format(RStrBuf *sb, const Mn103Insn *in);

/* Register-list mask bits (REG_LIST operands). */
#define MN103_REGS_D2 0x80
#define MN103_REGS_D3 0x40
#define MN103_REGS_A2 0x20
#define MN103_REGS_A3 0x10
#define MN103_REGS_OTHER 0x08
#define MN103_REGS_EXREG0 0x04
#define MN103_REGS_EXREG1 0x02
#define MN103_REGS_EXOTHER 0x01

#endif
