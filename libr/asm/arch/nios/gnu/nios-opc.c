/* Instruction opcode table for nios.
   Copyright (C) 2012-2018 Free Software Foundation, Inc.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include <string.h>
#include "ansidecl.h"
//#include "bfd.h"
#include "mybfd.h"
#include "symcat.h"
#include "nios-desc.h"
#include "nios-opc.h"
#include "libiberty.h"

/* The hash functions are recorded here to help keep assembler code out of
   the disassembler and vice versa.  */

static int asm_hash_insn_p PARAMS ((const CGEN_INSN *));
static unsigned int asm_hash_insn PARAMS ((const char *));
static int dis_hash_insn_p PARAMS ((const CGEN_INSN *));
static unsigned int dis_hash_insn PARAMS ((const char *, CGEN_INSN_INT));

/* Instruction formats.  */

#define F(f) & nios_cgen_ifld_table[NIOS_##f]
static const CGEN_IFMT ifmt_empty ATTRIBUTE_UNUSED = {
  0, 0, 0x0, { { 0 } }
};

static const CGEN_IFMT ifmt_ext8s16 ATTRIBUTE_UNUSED = {
  16, 16, 0xff80, { { F (F_OP9) }, { F (F_I1) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_sts8s16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_I10) }, { 0 } }
};

static const CGEN_IFMT ifmt_st8d16 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_addc16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RB) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_addi16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_I5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_or16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RBI5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_lds16 ATTRIBUTE_UNUSED = {
  16, 16, 0xe000, { { F (F_OP3) }, { F (F_I8) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldp16 ATTRIBUTE_UNUSED = {
  16, 16, 0xf000, { { F (F_OP4) }, { F (F_RP) }, { F (F_I5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_trap16 ATTRIBUTE_UNUSED = {
  16, 16, 0xff00, { { F (F_OP8) }, { F (F_O2) }, { F (F_I6V) }, { 0 } }
};

static const CGEN_IFMT ifmt_save16 ATTRIBUTE_UNUSED = {
  16, 16, 0xff00, { { F (F_OP8) }, { F (F_I8V) }, { 0 } }
};

static const CGEN_IFMT ifmt_restore16 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_bsr16 ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OP5) }, { F (F_I11_REL) }, { 0 } }
};

static const CGEN_IFMT ifmt_bsrr16 ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OP5) }, { F (F_BSRR_I6_REL) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_jmpc16 ATTRIBUTE_UNUSED = {
  16, 16, 0xff00, { { F (F_OP8) }, { F (F_I8V_REL_H) }, { 0 } }
};

static const CGEN_IFMT ifmt_skps16 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_X1) }, { F (F_I4W) }, { 0 } }
};

static const CGEN_IFMT ifmt_sts16s ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_I9) }, { F (F_O1) }, { 0 } }
};

static const CGEN_IFMT ifmt_movhi ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_I5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ext16d ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RB) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_sext16 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ext8s32 ATTRIBUTE_UNUSED = {
  16, 16, 0xff80, { { F (F_OP9) }, { F (F_I2) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ext16s ATTRIBUTE_UNUSED = {
  16, 16, 0xff80, { { F (F_OP9) }, { F (F_I1) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_or32 ATTRIBUTE_UNUSED = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RBI5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_lds32 ATTRIBUTE_UNUSED = {
  16, 16, 0xe000, { { F (F_OP3) }, { F (F_I8) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldp32 ATTRIBUTE_UNUSED = {
  16, 16, 0xf000, { { F (F_OP4) }, { F (F_RP) }, { F (F_I5) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_bsrr32 ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OP5) }, { F (F_BSRR_I6_REL) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_jmpc32 ATTRIBUTE_UNUSED = {
  16, 16, 0xff00, { { F (F_OP8) }, { F (F_I8V_REL_W) }, { 0 } }
};

static const CGEN_IFMT ifmt_pfx ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OP5) }, { F (F_I11) }, { 0 } }
};

#undef F

#define A(a) (1 << CGEN_INSN_##a)
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OPERAND(op) NIOS_OPERAND_##op
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The instruction table.  */

static const CGEN_OPCODE nios_cgen_insn_opcode_table[MAX_INSNS] =
{
  /* Special null first entry.
     A `num' value of zero is thus invalid.
     Also, the special `invalid' insn resides here.  */
  { { 0 } },
/* ext8s $m16_Ra,$i1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I1), 0 } },
    & ifmt_ext8s16, { 0x7400 }
  },
/* st8s [$m16_Ra],$m16_R0,$i1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_RA), ']', ',', OP (M16_R0), ',', OP (I1), 0 } },
    & ifmt_ext8s16, { 0x7600 }
  },
/* sts8s [$m16_sp,$i10],$m16_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_SP), ',', OP (I10), ']', ',', OP (M16_R0), 0 } },
    & ifmt_sts8s16, { 0x6000 }
  },
/* st8d [$m16_Ra],$m16_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_RA), ']', ',', OP (M16_R0), 0 } },
    & ifmt_st8d16, { 0x7e00 }
  },
/* wrctl $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7f00 }
  },
/* addc $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x6800 }
  },
/* subc $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x6c00 }
  },
/* add $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x0 }
  },
/* sub $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x800 }
  },
/* addi $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x400 }
  },
/* subi $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0xc00 }
  },
/* or $m16_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (RBI5), 0 } },
    & ifmt_or16, { 0x4000 }
  },
/* xor $m16_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (RBI5), 0 } },
    & ifmt_or16, { 0x4400 }
  },
/* and $m16_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (RBI5), 0 } },
    & ifmt_or16, { 0x3800 }
  },
/* andn $m16_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (RBI5), 0 } },
    & ifmt_or16, { 0x3c00 }
  },
/* lsl $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x1800 }
  },
/* lsr $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x2000 }
  },
/* asr $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x2800 }
  },
/* lsli $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x1c00 }
  },
/* lsri $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x2400 }
  },
/* asri $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x2c00 }
  },
/* not $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7c00 }
  },
/* neg $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7c20 }
  },
/* abs $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7c40 }
  },
/* mov $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x3000 }
  },
/* movi $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x3400 }
  },
/* bgen $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x4800 }
  },
/* cmp $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x1000 }
  },
/* cmpi $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x1400 }
  },
/* ext8d $m16_Ra,$m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x4c00 }
  },
/* sext8 $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7c60 }
  },
/* fill8 $m16_R0,$m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_R0), ',', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7e40 }
  },
/* lds $m16_Ra,[$m16_sp,$i8] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', '[', OP (M16_SP), ',', OP (I8), ']', 0 } },
    & ifmt_lds16, { 0xe000 }
  },
/* sts [$m16_sp,$i8],$m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_SP), ',', OP (I8), ']', ',', OP (M16_RA), 0 } },
    & ifmt_lds16, { 0xc000 }
  },
/* ldp $m16_Ra,[$m16_Rp,$i5] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', '[', OP (M16_RP), ',', OP (I5), ']', 0 } },
    & ifmt_ldp16, { 0xb000 }
  },
/* stp [$m16_Rp,$i5],$m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_RP), ',', OP (I5), ']', ',', OP (M16_RA), 0 } },
    & ifmt_ldp16, { 0xa000 }
  },
/* ld $m16_Ra,[$m16_Rb] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', '[', OP (M16_RB), ']', 0 } },
    & ifmt_addc16, { 0x5800 }
  },
/* st [$m16_Rb],$m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_RB), ']', ',', OP (M16_RA), 0 } },
    & ifmt_addc16, { 0x5c00 }
  },
/* trap $i6v */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I6V), 0 } },
    & ifmt_trap16, { 0x7900 }
  },
/* tret $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7dc0 }
  },
/* save $m16_sp,$save_i8v */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_SP), ',', OP (SAVE_I8V), 0 } },
    & ifmt_save16, { 0x7800 }
  },
/* restore */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_restore16, { 0x7da0 }
  },
/* bsr $rel11 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (REL11), 0 } },
    & ifmt_bsr16, { 0x8800 }
  },
/* bsrr $m16_Ra,$bsrr_rel6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (BSRR_REL6), 0 } },
    & ifmt_bsrr16, { 0x8800 }
  },
/* jmp $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7fc0 }
  },
/* call $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7fe0 }
  },
/* jmpc [$m16_i8v] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_I8V), ']', 0 } },
    & ifmt_jmpc16, { 0x7a00 }
  },
/* callc [$m16_i8v] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M16_I8V), ']', 0 } },
    & ifmt_jmpc16, { 0x7b00 }
  },
/* skp0 $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x5000 }
  },
/* skp1 $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_addi16, { 0x5400 }
  },
/* skprz $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7ec0 }
  },
/* skprnz $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7f40 }
  },
/* skps $i4w */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I4W), 0 } },
    & ifmt_skps16, { 0x7ee0 }
  },
/* rrc $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7cc0 }
  },
/* rlc $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7ca0 }
  },
/* rdctl $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7f20 }
  },
/* usr0 $m16_Ra, $m16_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (M16_RB), 0 } },
    & ifmt_addc16, { 0x7000 }
  },
/* usr1 $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7d20 }
  },
/* usr2 $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7d40 }
  },
/* usr3 $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7d60 }
  },
/* usr4 $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_st8d16, { 0x7d80 }
  },
/* sts8s [$m32_sp,$i10],$m32_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_SP), ',', OP (I10), ']', ',', OP (M32_R0), 0 } },
    & ifmt_sts8s16, { 0x6000 }
  },
/* sts16s [$m32_sp,$i9],$m32_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_SP), ',', OP (I9), ']', ',', OP (M32_R0), 0 } },
    & ifmt_sts16s, { 0x6400 }
  },
/* movhi $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x6c00 }
  },
/* ext16d $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x6800 }
  },
/* sext16 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7c80 }
  },
/* st16d [$m32_Ra],$m32_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RA), ']', ',', OP (M32_R0), 0 } },
    & ifmt_sext16, { 0x7e20 }
  },
/* fill16 $m32_R0,$m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_R0), ',', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7e60 }
  },
/* ext8s $m32_Ra,$i2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I2), 0 } },
    & ifmt_ext8s32, { 0x7400 }
  },
/* st8s [$m32_Ra],$m32_R0,$i2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RA), ']', ',', OP (M32_R0), ',', OP (I2), 0 } },
    & ifmt_ext8s32, { 0x7600 }
  },
/* ext16s $m32_Ra,$i1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I1), 0 } },
    & ifmt_ext16s, { 0x7480 }
  },
/* st16s [$m32_Ra],$m32_R0,$i1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RA), ']', ',', OP (M32_R0), ',', OP (I1), 0 } },
    & ifmt_ext16s, { 0x7680 }
  },
/* st8d [$m32_Ra],$m32_R0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RA), ']', ',', OP (M32_R0), 0 } },
    & ifmt_sext16, { 0x7e00 }
  },
/* wrctl $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7f00 }
  },
/* add $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x0 }
  },
/* sub $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x800 }
  },
/* addi $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x400 }
  },
/* subi $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0xc00 }
  },
/* or $m32_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (RBI5), 0 } },
    & ifmt_or32, { 0x4000 }
  },
/* xor $m32_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (RBI5), 0 } },
    & ifmt_or32, { 0x4400 }
  },
/* and $m32_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (RBI5), 0 } },
    & ifmt_or32, { 0x3800 }
  },
/* andn $m32_Ra,$Rbi5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (RBI5), 0 } },
    & ifmt_or32, { 0x3c00 }
  },
/* lsl $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x1800 }
  },
/* lsr $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x2000 }
  },
/* asr $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x2800 }
  },
/* lsli $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x1c00 }
  },
/* lsri $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x2400 }
  },
/* asri $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x2c00 }
  },
/* not $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7c00 }
  },
/* neg $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7c20 }
  },
/* abs $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7c40 }
  },
/* mov $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x3000 }
  },
/* movi $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x3400 }
  },
/* bgen $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x4800 }
  },
/* cmp $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x1000 }
  },
/* cmpi $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x1400 }
  },
/* ext8d $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x4c00 }
  },
/* sext8 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7c60 }
  },
/* fill8 $m32_R0,$m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_R0), ',', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7e40 }
  },
/* lds $m32_Ra,[$m32_sp,$i8] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', '[', OP (M32_SP), ',', OP (I8), ']', 0 } },
    & ifmt_lds32, { 0xe000 }
  },
/* sts [$m32_sp,$i8],$m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_SP), ',', OP (I8), ']', ',', OP (M32_RA), 0 } },
    & ifmt_lds32, { 0xc000 }
  },
/* ldp $m32_Ra,[$m32_Rp,$i5] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', '[', OP (M32_RP), ',', OP (I5), ']', 0 } },
    & ifmt_ldp32, { 0xb000 }
  },
/* stp [$m32_Rp,$i5],$m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RP), ',', OP (I5), ']', ',', OP (M32_RA), 0 } },
    & ifmt_ldp32, { 0xa000 }
  },
/* ld $m32_Ra,[$m32_Rb] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', '[', OP (M32_RB), ']', 0 } },
    & ifmt_ext16d, { 0x5800 }
  },
/* st [$m32_Rb],$m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_RB), ']', ',', OP (M32_RA), 0 } },
    & ifmt_ext16d, { 0x5c00 }
  },
/* trap $i6v */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I6V), 0 } },
    & ifmt_trap16, { 0x7900 }
  },
/* tret $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7dc0 }
  },
/* save $m32_sp,$save_i8v */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_SP), ',', OP (SAVE_I8V), 0 } },
    & ifmt_save16, { 0x7800 }
  },
/* restore */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_restore16, { 0x7da0 }
  },
/* bsr $rel11 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (REL11), 0 } },
    & ifmt_bsr16, { 0x8800 }
  },
/* bsrr $m32_Ra,$bsrr_rel6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (BSRR_REL6), 0 } },
    & ifmt_bsrr32, { 0x8800 }
  },
/* jmp $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7fc0 }
  },
/* call $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7fe0 }
  },
/* jmpc [$m32_i8v] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_I8V), ']', 0 } },
    & ifmt_jmpc32, { 0x7a00 }
  },
/* callc [$m32_i8v] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', '[', OP (M32_I8V), ']', 0 } },
    & ifmt_jmpc32, { 0x7b00 }
  },
/* skp0 $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x5000 }
  },
/* skp1 $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_movhi, { 0x5400 }
  },
/* skprz $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7ec0 }
  },
/* skprnz $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7f40 }
  },
/* skps $i4w */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I4W), 0 } },
    & ifmt_skps16, { 0x7ee0 }
  },
/* rrc $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7cc0 }
  },
/* rlc $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7ca0 }
  },
/* rdctl $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7f20 }
  },
/* pfx $i11 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I11), 0 } },
    & ifmt_pfx, { 0x9800 }
  },
/* br $rel11 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (REL11), 0 } },
    & ifmt_bsr16, { 0x8000 }
  },
/* swap $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7d00 }
  },
/* mstep $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7e80 }
  },
/* mul $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7ea0 }
  },
/* usr0 $m32_Ra,$m32_Rb */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (M32_RB), 0 } },
    & ifmt_ext16d, { 0x7000 }
  },
/* usr1 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7d20 }  
  },
/* usr2 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7d40 }  
  },
/* usr3 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7d60 }  
  },
/* usr4 $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_sext16, { 0x7d80 }  
  },
/* pfxio $i11 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I11), 0 } },
    & ifmt_pfx, { 0x9000 }
  },
};

#undef A
#undef MNEM
#undef OPERAND
#undef OP

/* Formats for ALIAS macro-insns.  */

#define F(f) & nios_cgen_ifld_table[NIOS_##f]

static const CGEN_IFMT ifmt_if016 = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_if116 = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifrz16 = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifrnz16 = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifs16 = {
  16, 16, 0xfff0, { { F (F_OP11) }, { F (F_X1) }, { F (F_I4W) }, { 0 } }
};

static const CGEN_IFMT ifmt_nop16 = {
  16, 16, 0xffff, { { F (F_OP6) }, { F (F_RA) }, { F (F_RB) }, { 0 } }
};

static const CGEN_IFMT ifmt_inc16 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_dec16 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_clr16 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_ret16 = {
  16, 16, 0xffff, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_lret16 = {
  16, 16, 0xffff, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_if032 = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_if132 = {
  16, 16, 0xfc00, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifrz32 = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifrnz32 = {
  16, 16, 0xffe0, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_ifs32 = {
  16, 16, 0xfff0, { { F (F_OP11) }, { F (F_X1) }, { F (F_I4W) }, { 0 } }
};

static const CGEN_IFMT ifmt_nop32 = {
  16, 16, 0xffff, { { F (F_OP6) }, { F (F_RA) }, { F (F_RB) }, { 0 } }
};

static const CGEN_IFMT ifmt_inc32 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_dec32 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_clr32 = {
  16, 16, 0xffe0, { { F (F_OP6) }, { F (F_RA) }, { F (F_I5) }, { 0 } }
};

static const CGEN_IFMT ifmt_ret32 = {
  16, 16, 0xffff, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

static const CGEN_IFMT ifmt_lret32 = {
  16, 16, 0xffff, { { F (F_OP11) }, { F (F_RA) }, { 0 } }
};

#undef F

/* Each non-simple macro entry points to an array of expansion possibilities.  */

#define A(a) (1 << CGEN_INSN_##a)
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OPERAND(op) NIOS_OPERAND_##op
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The macro instruction table.  */

static const CGEN_IBASE nios_cgen_macro_insn_table[] =
{
/* if0 $m16_Ra,$i5 */
  {
    -1, "if016", "if0", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* if1 $m16_Ra,$i5 */
  {
    -1, "if116", "if1", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* ifrz $m16_Ra */
  {
    -1, "ifrz16", "ifrz", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* ifrnz $m16_Ra */
  {
    -1, "ifrnz16", "ifrnz", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* ifs $i4wn */
  {
    -1, "ifs16", "ifs", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* nop */
  {
    -1, "nop16", "nop", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* inc $m16_Ra */
  {
    -1, "inc16", "inc", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* dec $m16_Ra */
  {
    -1, "dec16", "dec", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* clr $m16_Ra */
  {
    -1, "clr16", "clr", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* ret */
  {
    -1, "ret16", "ret", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* lret */
  {
    -1, "lret16", "lret", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS16) } } } }
  },
/* if0 $m32_Ra,$i5 */
  {
    -1, "if032", "if0", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* if1 $m32_Ra,$i5 */
  {
    -1, "if132", "if1", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* ifrz $m32_Ra */
  {
    -1, "ifrz32", "ifrz", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* ifrnz $m32_Ra */
  {
    -1, "ifrnz32", "ifrnz", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* ifs $i4wn */
  {
    -1, "ifs32", "ifs", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* nop */
  {
    -1, "nop32", "nop", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* inc $m32_Ra */
  {
    -1, "inc32", "inc", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* dec $m32_Ra */
  {
    -1, "dec32", "dec", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* clr $m32_Ra */
  {
    -1, "clr32", "clr", 16,
    { 0|A(NO_DIS)|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* ret */
  {
    -1, "ret32", "ret", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
/* lret */
  {
    -1, "lret32", "lret", 16,
    { 0|A(ALIAS), { { { (1<<MACH_NIOS32) } } } }
  },
};

/* The macro instruction opcode table.  */

static const CGEN_OPCODE nios_cgen_macro_insn_opcode_table[] =
{
/* if0 $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_if016, { 0x5400 }
  },
/* if1 $m16_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), ',', OP (I5), 0 } },
    & ifmt_if116, { 0x5000 }
  },
/* ifrz $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_ifrz16, { 0x7f40 }
  },
/* ifrnz $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_ifrnz16, { 0x7ec0 }
  },
/* ifs $i4wn */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I4WN), 0 } },
    & ifmt_ifs16, { 0x7ee0 }
  },
/* nop */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_nop16, { 0x3000 }
  },
/* inc $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_inc16, { 0x420 }
  },
/* dec $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_dec16, { 0xc20 }
  },
/* clr $m16_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M16_RA), 0 } },
    & ifmt_clr16, { 0x3400 }
  },
/* ret */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_ret16, { 0x7fdf }
  },
/* lret */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_lret16, { 0x7fcf }
  },
/* if0 $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_if032, { 0x5400 }
  },
/* if1 $m32_Ra,$i5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), ',', OP (I5), 0 } },
    & ifmt_if132, { 0x5000 }
  },
/* ifrz $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_ifrz32, { 0x7f40 }
  },
/* ifrnz $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_ifrnz32, { 0x7ec0 }
  },
/* ifs $i4wn */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (I4WN), 0 } },
    & ifmt_ifs32, { 0x7ee0 }
  },
/* nop */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_nop32, { 0x3000 }
  },
/* inc $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_inc32, { 0x420 }
  },
/* dec $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_dec32, { 0xc20 }
  },
/* clr $m32_Ra */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (M32_RA), 0 } },
    & ifmt_clr32, { 0x3400 }
  },
/* ret */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_ret32, { 0x7fdf }
  },
/* lret */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_lret32, { 0x7fcf }
  },
};

#undef A
#undef MNEM
#undef OPERAND
#undef OP

#ifndef CGEN_ASM_HASH_P
#define CGEN_ASM_HASH_P(insn) 1
#endif

#ifndef CGEN_DIS_HASH_P
#define CGEN_DIS_HASH_P(insn) 1
#endif

/* Return non-zero if INSN is to be added to the hash table.
   Targets are free to override CGEN_{ASM,DIS}_HASH_P in the .opc file.  */

static int
asm_hash_insn_p (const CGEN_INSN *insn)
{
  return CGEN_ASM_HASH_P (insn);
}

static int
dis_hash_insn_p (const CGEN_INSN *insn)
{
  /* If building the hash table and the NO-DIS attribute is present,
     ignore.  */
  if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_NO_DIS))
    return 0;
  return CGEN_DIS_HASH_P (insn);
}

#ifndef CGEN_ASM_HASH
#define CGEN_ASM_HASH_SIZE 127
#ifdef CGEN_MNEMONIC_OPERANDS
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE)
#else
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE) /*FIXME*/
#endif
#endif

/* It doesn't make much sense to provide a default here,
   but while this is under development we do.
   BUFFER is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

#ifndef CGEN_DIS_HASH
#define CGEN_DIS_HASH_SIZE 256
#define CGEN_DIS_HASH(buf, value) (*(unsigned char *) (buf))
#endif

/* The result is the hash value of the insn.
   Targets are free to override CGEN_{ASM,DIS}_HASH in the .opc file.  */

static unsigned int
asm_hash_insn (const char *mnem)
{
  return CGEN_ASM_HASH (mnem);
}

/* BUF is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

static unsigned int
dis_hash_insn (const char *buf, CGEN_INSN_INT value)
{
  return CGEN_DIS_HASH (buf, value);
}

/* Set the recorded length of the insn in the CGEN_FIELDS struct.  */

static void
set_fields_bitsize (CGEN_FIELDS *fields, int size)
{
  CGEN_FIELDS_BITSIZE (fields) = size;
}

/* Function to call before using the operand instance table.
   This plugs the opcode entries and macro instructions into the cpu table.  */

void
nios_cgen_init_opcode_table (CGEN_CPU_DESC cd)
{
  int i;
  int num_macros = (sizeof (nios_cgen_macro_insn_table) /
		    sizeof (nios_cgen_macro_insn_table[0]));
  const CGEN_IBASE *ib = & nios_cgen_macro_insn_table[0];
  const CGEN_OPCODE *oc = & nios_cgen_macro_insn_opcode_table[0];
  CGEN_INSN *insns = (CGEN_INSN *) xmalloc (num_macros * sizeof (CGEN_INSN));
  memset (insns, 0, num_macros * sizeof (CGEN_INSN));
  for (i = 0; i < num_macros; ++i)
    {
      insns[i].base = &ib[i];
      insns[i].opcode = &oc[i];
    }
  cd->macro_insn_table.init_entries = insns;
  cd->macro_insn_table.entry_size = sizeof (CGEN_IBASE);
  cd->macro_insn_table.num_init_entries = num_macros;

  oc = & nios_cgen_insn_opcode_table[0];
  insns = (CGEN_INSN *) cd->insn_table.init_entries;
  for (i = 0; i < MAX_INSNS; ++i)
    insns[i].opcode = &oc[i];

  cd->sizeof_fields = sizeof (CGEN_FIELDS);
  cd->set_fields_bitsize = set_fields_bitsize;

  cd->asm_hash_p = asm_hash_insn_p;
  cd->asm_hash = asm_hash_insn;
  cd->asm_hash_size = CGEN_ASM_HASH_SIZE;

  cd->dis_hash_p = dis_hash_insn_p;
  cd->dis_hash = dis_hash_insn;
  cd->dis_hash_size = CGEN_DIS_HASH_SIZE;
}
