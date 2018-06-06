/* CPU data header for nios.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright (C) 1996-2018 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#ifndef NIOS_CPU_H
#define NIOS_CPU_H

#ifdef __cplusplus
extern "C" {
#endif

#define CGEN_ARCH nios

/* Given symbol S, return nios_cgen_<S>.  */
#define CGEN_SYM(s) nios##_cgen_##s

/* Selected cpu families.  */
#define HAVE_CPU_NIOS16BF
#define HAVE_CPU_NIOS32BF

#define CGEN_INSN_LSB0_P 1

/* Minimum size of any insn (in bytes).  */
#define CGEN_MIN_INSN_SIZE 2

/* Maximum size of any insn (in bytes).  */
#define CGEN_MAX_INSN_SIZE 2

#define CGEN_INT_INSN_P 1

/* Maximum number of syntax elements in an instruction.  */
#define CGEN_ACTUAL_MAX_SYNTAX_ELEMENTS 16

/* CGEN_MNEMONIC_OPERANDS is defined if mnemonics have operands.
   e.g. In "b,a foo" the ",a" is an operand.  If mnemonics have operands
   we can't hash on everything up to the space.  */
#define CGEN_MNEMONIC_OPERANDS

/* Maximum number of fields in an instruction.  */
#define CGEN_ACTUAL_MAX_IFMT_OPERANDS 4

/* Enums.  */

/* Enum declaration for insn op6 enums.  */
typedef enum insn_op6 {
  OP_ADD = 0, OP_ADDI = 1, OP_SUB = 2, OP_SUBI = 3
 , OP_CMP = 4, OP_CMPI = 5, OP_LSL = 6, OP_LSLI = 7
 , OP_LSR = 8, OP_LSRI = 9, OP_ASR = 10, OP_ASRI = 11
 , OP_MOV = 12, OP_MOVI = 13, OP_AND = 14, OP_ANDN = 15
 , OP_OR = 16, OP_XOR = 17, OP_BGEN = 18, OP_EXT8D = 19
 , OP_SKP0 = 20, OP_SKP1 = 21, OP_LD = 22, OP_ST = 23
 , OP_STS8S = 24, OP_STS16S = 25, OP_ADDC = 26, OP_EXT16D = 26
 , OP_SUBC = 27, OP_MOVHI = 27, OP_USR0 = 28
} INSN_OP6;

/* Enum declaration for insn pfx enum.  */
typedef enum insn_pfx_hi {
  OP_PFX_HI = 19
} INSN_PFX_HI;

/* Enum declaration for insn op3 enums.  */
typedef enum insn_op3 {
  OP_STS = 6, OP_LDS = 7
} INSN_OP3;

/* Enum declaration for insn op4 enums.  */
typedef enum insn_op4 {
  OP_STP = 10, OP_LDP = 11
} INSN_OP4;

/* Enum declaration for insn op5 enums.  */
typedef enum insn_op5 {
  OP_BR = 16, OP_BSR = 17, OP_PFXIO = 18, OP_PFX = 19
} INSN_OP5;

/* Enum declaration for insn op8 enums.  */
typedef enum insn_op8 {
  OP_SAVE = 120, OP_TRAP = 121, OP_JMPC = 122, OP_CALLC = 123
} INSN_OP8;

/* Enum declaration for insn op9 enums.  */
typedef enum insn_op9 {
  OP_EXT8S = 232, OP_EXT16S = 233, OP_ST8S = 236, OP_ST16S = 237
} INSN_OP9;

/* Enum declaration for insn op11 enums.  */
typedef enum insn_op11 {
  OP_NOT = 992, OP_NEG = 993, OP_ABS = 994, OP_SEXT8 = 995
 , OP_SEXT16 = 996, OP_RLC = 997, OP_RRC = 998, OP_TRET = 1006
 , OP_RESTORE = 1005, OP_ST8D = 1008, OP_ST16D = 1009, OP_FILL8 = 1010
 , OP_FILL16 = 1011, OP_LDM = 1012, OP_STM = 1013, OP_SKPRZ = 1014
 , OP_SKPS = 1015, OP_WRCTL = 1016, OP_RDCTL = 1017, OP_SKPRNZ = 1018
 , OP_JMP = 1022, OP_CALL = 1023, OP_SWAP = 1000, OP_USR1 = 1001
 , OP_USR2 = 1002, OP_USR3 = 1003, OP_USR4 = 1004, OP_MSTEP = 1012
 , OP_MUL = 1013
} INSN_OP11;

/* Enum declaration for .  */
typedef enum ctl_names {
  H_CTL__CTL0 = 0, H_CTL__CTL1 = 1, H_CTL__CTL2 = 2, H_CTL__CTL3 = 3
 , H_CTL__CTL4 = 4, H_CTL__CTL5 = 5, H_CTL__STATUS = 0, H_CTL__ISTATUS = 1
 , H_CTL__WVALID = 2, H_CTL__CD_BANK = 3, H_CTL__ST_BANK = 4, H_CTL__LD_BANK = 5
} CTL_NAMES;

/* Enum declaration for .  */
typedef enum gr_names {
  H_GR__SP = 14, H_GR__FP = 30, H_GR__G0 = 0, H_GR__G1 = 1
 , H_GR__G2 = 2, H_GR__G3 = 3, H_GR__G4 = 4, H_GR__G5 = 5
 , H_GR__G6 = 6, H_GR__G7 = 7, H_GR__R0 = 0, H_GR__R1 = 1
 , H_GR__R2 = 2, H_GR__R3 = 3, H_GR__R4 = 4, H_GR__R5 = 5
 , H_GR__R6 = 6, H_GR__R7 = 7, H_GR__O0 = 8, H_GR__O1 = 9
 , H_GR__O2 = 10, H_GR__O3 = 11, H_GR__O4 = 12, H_GR__O5 = 13
 , H_GR__O6 = 14, H_GR__O7 = 15, H_GR__R8 = 8, H_GR__R9 = 9
 , H_GR__R10 = 10, H_GR__R11 = 11, H_GR__R12 = 12, H_GR__R13 = 13
 , H_GR__R14 = 14, H_GR__R15 = 15, H_GR__L0 = 16, H_GR__L1 = 17
 , H_GR__L2 = 18, H_GR__L3 = 19, H_GR__L4 = 20, H_GR__L5 = 21
 , H_GR__L6 = 22, H_GR__L7 = 23, H_GR__R16 = 16, H_GR__R17 = 17
 , H_GR__R18 = 18, H_GR__R19 = 19, H_GR__R20 = 20, H_GR__R21 = 21
 , H_GR__R22 = 22, H_GR__R23 = 23, H_GR__I0 = 24, H_GR__I1 = 25
 , H_GR__I2 = 26, H_GR__I3 = 27, H_GR__I4 = 28, H_GR__I5 = 29
 , H_GR__I6 = 30, H_GR__I7 = 31, H_GR__R24 = 24, H_GR__R25 = 25
 , H_GR__R26 = 26, H_GR__R27 = 27, H_GR__R28 = 28, H_GR__R29 = 29
 , H_GR__R30 = 30, H_GR__R31 = 31
} GR_NAMES;

/* Enum declaration for .  */
typedef enum gr0_name {
  H_GR0__R0
} GR0_NAME;

/* Enum declaration for .  */
typedef enum bp_names {
  H_BP__L0 = 0, H_BP__L1 = 1, H_BP__L2 = 2, H_BP__L3 = 3
 , H_BP__R16 = 0, H_BP__R17 = 1, H_BP__R18 = 2, H_BP__R19 = 3
} BP_NAMES;

/* Attributes.  */

/* Enum declaration for machine type selection.  */
typedef enum mach_attr {
  MACH_BASE, MACH_NIOS16, MACH_NIOS32, MACH_MAX
} MACH_ATTR;

/* Enum declaration for instruction set selection.  */
typedef enum isa_attr {
  ISA_NIOS, ISA_MAX
} ISA_ATTR;

/* Number of architecture variants.  */
#define MAX_ISAS  1
#define MAX_MACHS ((int) MACH_MAX)

/* Ifield support.  */

/* Ifield attribute indices.  */

/* Enum declaration for cgen_ifld attrs.  */
typedef enum cgen_ifld_attr {
  CGEN_IFLD_VIRTUAL, CGEN_IFLD_PCREL_ADDR, CGEN_IFLD_ABS_ADDR, CGEN_IFLD_RESERVED
 , CGEN_IFLD_SIGN_OPT, CGEN_IFLD_SIGNED, CGEN_IFLD_END_BOOLS, CGEN_IFLD_START_NBOOLS = 31
 , CGEN_IFLD_MACH, CGEN_IFLD_END_NBOOLS
} CGEN_IFLD_ATTR;

/* Number of non-boolean elements in cgen_ifld_attr.  */
#define CGEN_IFLD_NBOOL_ATTRS (CGEN_IFLD_END_NBOOLS - CGEN_IFLD_START_NBOOLS - 1)

/* Enum declaration for nios ifield types.  */
typedef enum ifield_type {
  NIOS_F_NIL, NIOS_F_ANYOF, NIOS_F_OP6, NIOS_F_OP3
 , NIOS_F_OP4, NIOS_F_OP5, NIOS_F_OP5_HI, NIOS_F_OP8
 , NIOS_F_OP9, NIOS_F_OP11, NIOS_F_RA, NIOS_F_RB
 , NIOS_F_RBI5, NIOS_F_RZ, NIOS_F_RP, NIOS_F_CTLC
 , NIOS_F_I2, NIOS_F_I4W, NIOS_F_X1, NIOS_F_O1
 , NIOS_F_O2, NIOS_F_I5, NIOS_F_I6V, NIOS_F_I8
 , NIOS_F_I8V, NIOS_F_I9, NIOS_F_I10, NIOS_F_I11
 , NIOS_F_I6_REL_H, NIOS_F_I6_REL_W, NIOS_F_BSRR_I6_REL, NIOS_F_I8V_REL_H
 , NIOS_F_I8V_REL_W, NIOS_F_I11_REL, NIOS_F_I1, NIOS_F_MAX
} IFIELD_TYPE;

#define MAX_IFLD ((int) NIOS_F_MAX)

/* Hardware attribute indices.  */

/* Enum declaration for cgen_hw attrs.  */
typedef enum cgen_hw_attr {
  CGEN_HW_VIRTUAL, CGEN_HW_CACHE_ADDR, CGEN_HW_PC, CGEN_HW_PROFILE
 , CGEN_HW_END_BOOLS, CGEN_HW_START_NBOOLS = 31, CGEN_HW_MACH, CGEN_HW_END_NBOOLS
} CGEN_HW_ATTR;

/* Number of non-boolean elements in cgen_hw_attr.  */
#define CGEN_HW_NBOOL_ATTRS (CGEN_HW_END_NBOOLS - CGEN_HW_START_NBOOLS - 1)

/* Enum declaration for nios hardware types.  */
typedef enum cgen_hw_type {
  HW_H_MEMORY, HW_H_SINT, HW_H_UINT, HW_H_ADDR
 , HW_H_IADDR, HW_H_PC, HW_H_CWP, HW_H_OLD_CWP
 , HW_H_IPRI, HW_H_ZERO, HW_H_TEBIT, HW_H_NBIT
 , HW_H_ZBIT, HW_H_VBIT, HW_H_CBIT, HW_H_PBIT
 , HW_H_SBIT, HW_H_WBIT, HW_H_STATUS, HW_H_K
 , HW_H_M16_GR, HW_H_M16_GR0, HW_H_M16_BP, HW_H_M16_RZ
 , HW_H_M16_SP, HW_H_M16_CTL, HW_H_M32_GR, HW_H_M32_GR0
 , HW_H_M32_BP, HW_H_M32_RZ, HW_H_M32_SP, HW_H_M32_CTL
 , HW_MAX
} CGEN_HW_TYPE;

#define MAX_HW ((int) HW_MAX)

/* Operand attribute indices.  */

/* Enum declaration for cgen_operand attrs.  */
typedef enum cgen_operand_attr {
  CGEN_OPERAND_VIRTUAL, CGEN_OPERAND_PCREL_ADDR, CGEN_OPERAND_ABS_ADDR, CGEN_OPERAND_SIGN_OPT
 , CGEN_OPERAND_SIGNED, CGEN_OPERAND_NEGATIVE, CGEN_OPERAND_RELAX, CGEN_OPERAND_SEM_ONLY
 , CGEN_OPERAND_HASH_PREFIX, CGEN_OPERAND_END_BOOLS, CGEN_OPERAND_START_NBOOLS = 31, CGEN_OPERAND_MACH
 , CGEN_OPERAND_END_NBOOLS
} CGEN_OPERAND_ATTR;

/* Number of non-boolean elements in cgen_operand_attr.  */
#define CGEN_OPERAND_NBOOL_ATTRS (CGEN_OPERAND_END_NBOOLS - CGEN_OPERAND_START_NBOOLS - 1)

/* Enum declaration for nios operand types.  */
typedef enum cgen_operand_type {
  NIOS_OPERAND_PC, NIOS_OPERAND_K, NIOS_OPERAND_CTLC, NIOS_OPERAND_XRA
 , NIOS_OPERAND_X1, NIOS_OPERAND_O1, NIOS_OPERAND_O2, NIOS_OPERAND_I1
 , NIOS_OPERAND_I2, NIOS_OPERAND_SI5, NIOS_OPERAND_I8, NIOS_OPERAND_I8V
 , NIOS_OPERAND_I6V, NIOS_OPERAND_SI11, NIOS_OPERAND_REL11, NIOS_OPERAND_BSRR_REL6
 , NIOS_OPERAND_NBIT, NIOS_OPERAND_VBIT, NIOS_OPERAND_ZBIT, NIOS_OPERAND_CBIT
 , NIOS_OPERAND_TEBIT, NIOS_OPERAND_PBIT, NIOS_OPERAND_SBIT, NIOS_OPERAND_WBIT
 , NIOS_OPERAND_I4W, NIOS_OPERAND_I4WN, NIOS_OPERAND_I5, NIOS_OPERAND_SAVE_I8V
 , NIOS_OPERAND_I11, NIOS_OPERAND_I10, NIOS_OPERAND_I9, NIOS_OPERAND_I16
 , NIOS_OPERAND_I32, NIOS_OPERAND_RBI5, NIOS_OPERAND_M16_RA, NIOS_OPERAND_M16_RB
 , NIOS_OPERAND_M16_R0, NIOS_OPERAND_M16_SP, NIOS_OPERAND_M16_RP, NIOS_OPERAND_M16_RZ
 , NIOS_OPERAND_M16_I6, NIOS_OPERAND_M16_I8V, NIOS_OPERAND_M32_RA, NIOS_OPERAND_M32_RB
 , NIOS_OPERAND_M32_R0, NIOS_OPERAND_M32_SP, NIOS_OPERAND_M32_RP, NIOS_OPERAND_M32_RZ
 , NIOS_OPERAND_M32_I6, NIOS_OPERAND_M32_I8V, NIOS_OPERAND_MAX
} CGEN_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS ((int) NIOS_OPERAND_MAX)

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 8

/* Insn attribute indices.  */

/* Enum declaration for cgen_insn attrs.  */
typedef enum cgen_insn_attr {
  CGEN_INSN_ALIAS, CGEN_INSN_VIRTUAL, CGEN_INSN_UNCOND_CTI, CGEN_INSN_COND_CTI
 , CGEN_INSN_SKIP_CTI, CGEN_INSN_DELAY_SLOT, CGEN_INSN_RELAXABLE, CGEN_INSN_RELAXED
 , CGEN_INSN_NO_DIS, CGEN_INSN_PBB, CGEN_INSN_PREFIX, CGEN_INSN_PREFIXED_INSN
 , CGEN_INSN_SKIP_INSN, CGEN_INSN_DUAL_MODE, CGEN_INSN_END_BOOLS, CGEN_INSN_START_NBOOLS = 31
 , CGEN_INSN_MACH, CGEN_INSN_END_NBOOLS
} CGEN_INSN_ATTR;

/* Number of non-boolean elements in cgen_insn_attr.  */
#define CGEN_INSN_NBOOL_ATTRS (CGEN_INSN_END_NBOOLS - CGEN_INSN_START_NBOOLS - 1)

/* cgen.h uses things we just defined.  */
#include "opcode/cgen.h"

extern const struct cgen_ifld nios_cgen_ifld_table[];

/* Attributes.  */
extern const CGEN_ATTR_TABLE nios_cgen_hardware_attr_table[];
extern const CGEN_ATTR_TABLE nios_cgen_ifield_attr_table[];
extern const CGEN_ATTR_TABLE nios_cgen_operand_attr_table[];
extern const CGEN_ATTR_TABLE nios_cgen_insn_attr_table[];

/* Hardware decls.  */

extern CGEN_KEYWORD nios_cgen_opval_gr_names;
extern CGEN_KEYWORD nios_cgen_opval_h_m16_gr0;
extern CGEN_KEYWORD nios_cgen_opval_bp_names;
extern CGEN_KEYWORD nios_cgen_opval_gr_names;
extern CGEN_KEYWORD nios_cgen_opval_h_m16_sp;
extern CGEN_KEYWORD nios_cgen_opval_ctl_names;
extern CGEN_KEYWORD nios_cgen_opval_gr_names;
extern CGEN_KEYWORD nios_cgen_opval_gr0_name;
extern CGEN_KEYWORD nios_cgen_opval_bp_names;
extern CGEN_KEYWORD nios_cgen_opval_gr_names;
extern CGEN_KEYWORD nios_cgen_opval_h_m32_sp;
extern CGEN_KEYWORD nios_cgen_opval_ctl_names;

extern const CGEN_HW_ENTRY nios_cgen_hw_table[];

#ifndef opcodes_error_handler
#define opcodes_error_handler(...) \
  fprintf (stderr, __VA_ARGS__); fputc ('\n', stderr)
#endif

   #ifdef __cplusplus
   }
   #endif

#endif /* NIOS_CPU_H */
