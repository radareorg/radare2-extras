/* CPU data for nios.

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

#include "sysdep.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "ansidecl.h"
//#include "bfd.h"
#include "mybfd.h"
#include "symcat.h"
#include "nios-desc.h"
#include "nios-opc.h"
#include "opintl.h"
#include "libiberty.h"
#include "xregex.h"

/* Attributes.  */

static const CGEN_ATTR_ENTRY bool_attr[] =
{
  { "#f", 0 },
  { "#t", 1 },
  { 0, 0 }
};

static const CGEN_ATTR_ENTRY MACH_attr[] ATTRIBUTE_UNUSED =
{
  { "base", MACH_BASE },
  { "nios16", MACH_NIOS16 },
  { "nios32", MACH_NIOS32 },
  { "max", MACH_MAX },
  { 0, 0 }
};

static const CGEN_ATTR_ENTRY ISA_attr[] ATTRIBUTE_UNUSED =
{
  { "nios", ISA_NIOS },
  { "max", ISA_MAX },
  { 0, 0 }
};

const CGEN_ATTR_TABLE nios_cgen_ifield_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "PCREL-ADDR", &bool_attr[0], &bool_attr[0] },
  { "ABS-ADDR", &bool_attr[0], &bool_attr[0] },
  { "RESERVED", &bool_attr[0], &bool_attr[0] },
  { "SIGN-OPT", &bool_attr[0], &bool_attr[0] },
  { "SIGNED", &bool_attr[0], &bool_attr[0] },
  { "RELOC", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE nios_cgen_hardware_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "CACHE-ADDR", &bool_attr[0], &bool_attr[0] },
  { "PC", &bool_attr[0], &bool_attr[0] },
  { "PROFILE", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE nios_cgen_operand_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "PCREL-ADDR", &bool_attr[0], &bool_attr[0] },
  { "ABS-ADDR", &bool_attr[0], &bool_attr[0] },
  { "SIGN-OPT", &bool_attr[0], &bool_attr[0] },
  { "SIGNED", &bool_attr[0], &bool_attr[0] },
  { "NEGATIVE", &bool_attr[0], &bool_attr[0] },
  { "RELAX", &bool_attr[0], &bool_attr[0] },
  { "SEM-ONLY", &bool_attr[0], &bool_attr[0] },
  { "HASH-PREFIX", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE nios_cgen_insn_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "ALIAS", &bool_attr[0], &bool_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "UNCOND-CTI", &bool_attr[0], &bool_attr[0] },
  { "COND-CTI", &bool_attr[0], &bool_attr[0] },
  { "SKIP-CTI", &bool_attr[0], &bool_attr[0] },
  { "DELAY-SLOT", &bool_attr[0], &bool_attr[0] },
  { "RELAXABLE", &bool_attr[0], &bool_attr[0] },
  { "RELAXED", &bool_attr[0], &bool_attr[0] },
  { "NO-DIS", &bool_attr[0], &bool_attr[0] },
  { "PBB", &bool_attr[0], &bool_attr[0] },
  { "PREFIX", &bool_attr[0], &bool_attr[0] },
  { "PREFIXED-INSN", &bool_attr[0], &bool_attr[0] },
  { "SKIP-INSN", &bool_attr[0], &bool_attr[0] },
  { "DUAL-MODE", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

/* Instruction set variants.  */

static const CGEN_ISA nios_cgen_isa_table[] = {
  { "nios", 16, 16, 16, 16,  },
  { 0, 0, 0, 0, 0 }
};

/* Machine variants.  */

static const CGEN_MACH nios_cgen_mach_table[] = {
  { "nios16", "nios16", MACH_NIOS16, 0 },
  { "nios32", "nios32", MACH_NIOS32, 0 },
  { 0, 0, 0, 0 }
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_ctl_names_entries[] =
{
  { "ctl0", 0 },
  { "ctl1", 1 },
  { "ctl2", 2 },
  { "ctl3", 3 },
  { "ctl4", 4 },
  { "ctl5", 5 },
  { "status", 0 },
  { "istatus", 1 },
  { "wvalid", 2 },
  { "cd_bank", 3 },
  { "st_bank", 4 },
  { "ld_bank", 5 }
};

CGEN_KEYWORD nios_cgen_opval_ctl_names =
{
  & nios_cgen_opval_ctl_names_entries[0],
  12,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_gr_names_entries[] =
{
  { "sp", 14 },
  { "fp", 30 },
  { "g0", 0 },
  { "g1", 1 },
  { "g2", 2 },
  { "g3", 3 },
  { "g4", 4 },
  { "g5", 5 },
  { "g6", 6 },
  { "g7", 7 },
  { "r0", 0 },
  { "r1", 1 },
  { "r2", 2 },
  { "r3", 3 },
  { "r4", 4 },
  { "r5", 5 },
  { "r6", 6 },
  { "r7", 7 },
  { "o0", 8 },
  { "o1", 9 },
  { "o2", 10 },
  { "o3", 11 },
  { "o4", 12 },
  { "o5", 13 },
  { "o6", 14 },
  { "o7", 15 },
  { "r8", 8 },
  { "r9", 9 },
  { "r10", 10 },
  { "r11", 11 },
  { "r12", 12 },
  { "r13", 13 },
  { "r14", 14 },
  { "r15", 15 },
  { "l0", 16 },
  { "l1", 17 },
  { "l2", 18 },
  { "l3", 19 },
  { "l4", 20 },
  { "l5", 21 },
  { "l6", 22 },
  { "l7", 23 },
  { "r16", 16 },
  { "r17", 17 },
  { "r18", 18 },
  { "r19", 19 },
  { "r20", 20 },
  { "r21", 21 },
  { "r22", 22 },
  { "r23", 23 },
  { "i0", 24 },
  { "i1", 25 },
  { "i2", 26 },
  { "i3", 27 },
  { "i4", 28 },
  { "i5", 29 },
  { "i6", 30 },
  { "i7", 31 },
  { "r24", 24 },
  { "r25", 25 },
  { "r26", 26 },
  { "r27", 27 },
  { "r28", 28 },
  { "r29", 29 },
  { "r30", 30 },
  { "r31", 31 }
};

CGEN_KEYWORD nios_cgen_opval_gr_names =
{
  & nios_cgen_opval_gr_names_entries[0],
  66,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_gr0_name_entries[] =
{
  { "r0", 0 }
};

CGEN_KEYWORD nios_cgen_opval_gr0_name =
{
  & nios_cgen_opval_gr0_name_entries[0],
  1,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_bp_names_entries[] =
{
  { "l0", 0 },
  { "l1", 1 },
  { "l2", 2 },
  { "l3", 3 },
  { "r16", 0 },
  { "r17", 1 },
  { "r18", 2 },
  { "r19", 3 }
};

CGEN_KEYWORD nios_cgen_opval_bp_names =
{
  & nios_cgen_opval_bp_names_entries[0],
  8,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_h_m16_gr0_entries[] =
{
  { "r0", 0 }
};

CGEN_KEYWORD nios_cgen_opval_h_m16_gr0 =
{
  & nios_cgen_opval_h_m16_gr0_entries[0],
  1,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_h_m16_sp_entries[] =
{
  { "sp", 0 }
};

CGEN_KEYWORD nios_cgen_opval_h_m16_sp =
{
  & nios_cgen_opval_h_m16_sp_entries[0],
  1
};

static CGEN_KEYWORD_ENTRY nios_cgen_opval_h_m32_sp_entries[] =
{
  { "sp", 0 }
};

CGEN_KEYWORD nios_cgen_opval_h_m32_sp =
{
  & nios_cgen_opval_h_m32_sp_entries[0],
  1
};



/* The hardware table.  */

#define A(a) (1 << CGEN_HW_##a)

const CGEN_HW_ENTRY nios_cgen_hw_table[] =
{
  { "h-memory", HW_H_MEMORY, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-sint", HW_H_SINT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-uint", HW_H_UINT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-addr", HW_H_ADDR, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-iaddr", HW_H_IADDR, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-pc", HW_H_PC, CGEN_ASM_NONE, 0, { 0|A(PROFILE)|A(PC), { { { (1<<MACH_BASE) } } } } },
  { "h-cwp", HW_H_CWP, CGEN_ASM_NONE, 0, { 0|A(PROFILE), { { { (1<<MACH_BASE) } } } } },
  { "h-old-cwp", HW_H_OLD_CWP, CGEN_ASM_NONE, 0, { 0|A(PROFILE), { { { (1<<MACH_BASE) } } } } },
  { "h-ipri", HW_H_IPRI, CGEN_ASM_NONE, 0, { 0|A(CACHE_ADDR)|A(PROFILE), { { { (1<<MACH_BASE) } } } } },
  { "h-zero", HW_H_ZERO, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-tebit", HW_H_TEBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-nbit", HW_H_NBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-zbit", HW_H_ZBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-vbit", HW_H_VBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-cbit", HW_H_CBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-pbit", HW_H_PBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-sbit", HW_H_SBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-wbit", HW_H_WBIT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE) } } } } },
  { "h-status", HW_H_STATUS, CGEN_ASM_NONE, 0, { 0|A(PROFILE), { { { (1<<MACH_BASE) } } } } },
  { "h-k", HW_H_K, CGEN_ASM_NONE, 0, { 0|A(CACHE_ADDR)|A(PROFILE), { { { (1<<MACH_BASE) } } } } },
  { "h-m16-gr", HW_H_M16_GR, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_gr_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m16-gr0", HW_H_M16_GR0, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_h_m16_gr0, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m16-bp", HW_H_M16_BP, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_bp_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m16-rz", HW_H_M16_RZ, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_gr_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m16-sp", HW_H_M16_SP, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_h_m16_sp, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m16-ctl", HW_H_M16_CTL, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_ctl_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS16) } } } } },
  { "h-m32-gr", HW_H_M32_GR, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_gr_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { "h-m32-gr0", HW_H_M32_GR0, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_gr0_name, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { "h-m32-bp", HW_H_M32_BP, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_bp_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { "h-m32-rz", HW_H_M32_RZ, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_gr_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { "h-m32-sp", HW_H_M32_SP, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_h_m32_sp, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { "h-m32-ctl", HW_H_M32_CTL, CGEN_ASM_KEYWORD, (PTR) & nios_cgen_opval_ctl_names, { 0|A(VIRTUAL), { { { (1<<MACH_NIOS32) } } } } },
  { 0 }
};

#undef A

/* The instruction field table.  */

#define A(a) (1 << CGEN_IFLD_##a)

const CGEN_IFLD nios_cgen_ifld_table[] =
{
  { NIOS_F_NIL, "f-nil", 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_ANYOF, "f-anyof", 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP6, "f-op6", 0, 16, 15, 6, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP3, "f-op3", 0, 16, 15, 3, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP4, "f-op4", 0, 16, 15, 4, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP5, "f-op5", 0, 16, 15, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP5_HI, "f-op5-hi", 16, 16, 15, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP8, "f-op8", 0, 16, 15, 8, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP9, "f-op9", 0, 16, 15, 9, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_OP11, "f-op11", 0, 16, 15, 11, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_RA, "f-Ra", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_RB, "f-Rb", 0, 16, 9, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_RBI5, "f-Rbi5", 0, 16, 9, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_RZ, "f-Rz", 0, 16, 1, 2, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_RP, "f-Rp", 0, 16, 11, 2, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_CTLC, "f-CTLc", 0, 16, 4, 3, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I2, "f-i2", 0, 16, 6, 2, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I4W, "f-i4w", 0, 16, 3, 4, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_X1, "f-x1", 0, 16, 4, 1, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_O1, "f-o1", 0, 16, 5, 1, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_O2, "f-o2", 0, 16, 7, 2, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I5, "f-i5", 0, 16, 9, 5, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I6V, "f-i6v", 0, 16, 5, 6, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I8, "f-i8", 0, 16, 12, 8, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I8V, "f-i8v", 0, 16, 7, 8, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I9, "f-i9", 0, 16, 9, 9, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I10, "f-i10", 0, 16, 9, 10, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I11, "f-i11", 0, 16, 10, 11, { 0, { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I6_REL_H, "f-i6-rel-h", 0, 16, 10, 6, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I6_REL_W, "f-i6-rel-w", 0, 16, 10, 6, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_BSRR_I6_REL, "f-bsrr-i6-rel", 0, 16, 10, 6, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I8V_REL_H, "f-i8v-rel-h", 0, 16, 7, 8, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I8V_REL_W, "f-i8v-rel-w", 0, 16, 7, 8, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I11_REL, "f-i11-rel", 0, 16, 10, 11, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE) } } } }  },
  { NIOS_F_I1, "f-i1", 0, 16, 6, 2, { 0, { { { (1<<MACH_BASE) } } } }  },
  { 0 }
};

#undef A

/* The operand table.  */

#define A(a) (1 << CGEN_OPERAND_##a)
#define OPERAND(op) NIOS_OPERAND_##op

const CGEN_OPERAND nios_cgen_operand_table[] =
{
/* pc: program counter */
  { "pc", NIOS_OPERAND_PC, HW_H_PC, 0, 0,
    { 0, { (const PTR) &nios_cgen_ifld_table[NIOS_F_NIL] } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* K: K register */
  { "K", NIOS_OPERAND_K, HW_H_K, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* CTLc: control register index */
  { "CTLc", NIOS_OPERAND_CTLC, HW_H_UINT, 4, 3,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* xRa: Ra ignored */
  { "xRa", NIOS_OPERAND_XRA, HW_H_UINT, 4, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* x1: 1 bit ignored */
  { "x1", NIOS_OPERAND_X1, HW_H_UINT, 4, 1,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* o1: zero-bit */
  { "o1", NIOS_OPERAND_O1, HW_H_ZERO, 5, 1,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* o2: 2 zero bits */
  { "o2", NIOS_OPERAND_O2, HW_H_ZERO, 7, 2,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* i1: 1 bit unsigned immediate */
  { "i1", NIOS_OPERAND_I1, HW_H_UINT, 6, 2,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i2: 2 bit unsigned immediate */
  { "i2", NIOS_OPERAND_I2, HW_H_UINT, 6, 2,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* si5: 5 bit signed immediate */
  { "si5", NIOS_OPERAND_SI5, HW_H_SINT, 9, 5,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i8: 8 bit unsigned immediate */
  { "i8", NIOS_OPERAND_I8, HW_H_UINT, 12, 8,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i8v: 8 bit unsigned immediate v */
  { "i8v", NIOS_OPERAND_I8V, HW_H_UINT, 7, 8,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i6v: 6 bit unsigned immediate v */
  { "i6v", NIOS_OPERAND_I6V, HW_H_UINT, 5, 6,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* si11: 11 bit signed immediate */
  { "si11", NIOS_OPERAND_SI11, HW_H_SINT, 10, 11,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* rel11: 11 bit relative address */
  { "rel11", NIOS_OPERAND_REL11, HW_H_IADDR, 10, 11,
    { 0, { (const PTR) 0 } },
    { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* bsrr_rel6: dummy 6 bit relative address */
  { "bsrr_rel6", NIOS_OPERAND_BSRR_REL6, HW_H_IADDR, 10, 6,
    { 0, { (const PTR) 0 } },
    { 0|A(RELAX)|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* nbit: negative    bit */
  { "nbit", NIOS_OPERAND_NBIT, HW_H_NBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* vbit: overflow    bit */
  { "vbit", NIOS_OPERAND_VBIT, HW_H_VBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* zbit: zero        bit */
  { "zbit", NIOS_OPERAND_ZBIT, HW_H_ZBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* cbit: carry       bit */
  { "cbit", NIOS_OPERAND_CBIT, HW_H_CBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* tebit: trap-enable bit */
  { "tebit", NIOS_OPERAND_TEBIT, HW_H_TEBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* pbit: prefix      bit */
  { "pbit", NIOS_OPERAND_PBIT, HW_H_PBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* sbit: skip        bit */
  { "sbit", NIOS_OPERAND_SBIT, HW_H_SBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* wbit: window chg  bit */
  { "wbit", NIOS_OPERAND_WBIT, HW_H_WBIT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* i4w: 4 bit condition code index */
  { "i4w", NIOS_OPERAND_I4W, HW_H_UINT, 3, 4,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i4wn: 4 bit condition code index reversed */
  { "i4wn", NIOS_OPERAND_I4WN, HW_H_UINT, 3, 4,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i5: 5 bit unsigned immediate */
  { "i5", NIOS_OPERAND_I5, HW_H_UINT, 9, 5,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* save_i8v: 8 bit unsigned immediate for save insn */
  { "save_i8v", NIOS_OPERAND_SAVE_I8V, HW_H_UINT, 7, 8,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i11: 11 bit unsigned immediate */
  { "i11", NIOS_OPERAND_I11, HW_H_UINT, 10, 11,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i10: 10 bit unsigned immediate */
  { "i10", NIOS_OPERAND_I10, HW_H_UINT, 9, 10,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i9: 9 bit unsigned immediate */
  { "i9", NIOS_OPERAND_I9, HW_H_UINT, 9, 9,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX), { { { (1<<MACH_BASE), 0 } } } }  },
/* i16: 16 bit unsigned immediate */
  { "i16", NIOS_OPERAND_I16, HW_H_UINT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX)|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* i32: 32 bit unsigned immediate */
  { "i32", NIOS_OPERAND_I32, HW_H_UINT, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0|A(HASH_PREFIX)|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* Rbi5: 5 bit register or unsigned immediate */
  { "Rbi5", NIOS_OPERAND_RBI5, HW_H_UINT, 9, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* m16_Ra: source register a */
  { "m16_Ra", NIOS_OPERAND_M16_RA, HW_H_M16_GR, 4, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_Rb: source register b */
  { "m16_Rb", NIOS_OPERAND_M16_RB, HW_H_M16_GR, 9, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_R0: source register 0 */
  { "m16_R0", NIOS_OPERAND_M16_R0, HW_H_M16_GR0, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_sp: stack pointer */
  { "m16_sp", NIOS_OPERAND_M16_SP, HW_H_M16_SP, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_Rp: base pointer register */
  { "m16_Rp", NIOS_OPERAND_M16_RP, HW_H_M16_BP, 11, 2,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_Rz: ctl target register */
  { "m16_Rz", NIOS_OPERAND_M16_RZ, HW_H_M16_RZ, 1, 2,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_i6: 6-bit half-word pc rel */
  { "m16_i6", NIOS_OPERAND_M16_I6, HW_H_IADDR, 10, 6,
    { 0, { (const PTR) 0 } },
    { 0|A(PCREL_ADDR), { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m16_i8v: 8-bit half-word pc rel */
  { "m16_i8v", NIOS_OPERAND_M16_I8V, HW_H_IADDR, 7, 8,
    { 0, { (const PTR) 0 } },
    { 0|A(PCREL_ADDR), { { { (1<<MACH_NIOS16), 0 } } } }  },
/* m32_Ra: source register a */
  { "m32_Ra", NIOS_OPERAND_M32_RA, HW_H_M32_GR, 4, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_Rb: source register b */
  { "m32_Rb", NIOS_OPERAND_M32_RB, HW_H_M32_GR, 9, 5,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_R0: source register 0 */
  { "m32_R0", NIOS_OPERAND_M32_R0, HW_H_M32_GR0, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_sp: stack pointer */
  { "m32_sp", NIOS_OPERAND_M32_SP, HW_H_M32_SP, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_Rp: base pointer register */
  { "m32_Rp", NIOS_OPERAND_M32_RP, HW_H_M32_BP, 11, 2,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_Rz: ctl target register */
  { "m32_Rz", NIOS_OPERAND_M32_RZ, HW_H_M32_RZ, 1, 2,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_i6: 6-bit word pc rel */
  { "m32_i6", NIOS_OPERAND_M32_I6, HW_H_IADDR, 10, 6,
    { 0, { (const PTR) 0 } },
    { 0|A(PCREL_ADDR), { { { (1<<MACH_NIOS32), 0 } } } }  },
/* m32_i8v: 8-bit word pc rel */
  { "m32_i8v", NIOS_OPERAND_M32_I8V, HW_H_IADDR, 7, 8,
    { 0, { (const PTR) 0 } },
    { 0|A(PCREL_ADDR), { { { (1<<MACH_NIOS32), 0 } } } }  },
/* sentinel */
  { 0, 0, 0, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_NIOS32), 0 } } } } }
};

#undef A


/* The instruction table.  */

#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))
#define A(a) (1 << CGEN_INSN_##a)

static const CGEN_IBASE nios_cgen_insn_table[MAX_INSNS] =
{
  /* Special null first entry.
     A `num' value of zero is thus invalid.
     Also, the special `invalid' insn resides here.  */
  { 0, 0, 0 },
/* ext8s $m16_Ra,$i1 */
  {
    NIOS_INSN_EXT8S16, "ext8s16", "ext8s", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* st8s [$m16_Ra],$m16_R0,$i1 */
  {
    NIOS_INSN_ST8S16, "st8s16", "st8s", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* sts8s [$m16_sp,$i10],$m16_R0 */
  {
    NIOS_INSN_STS8S16, "sts8s16", "sts8s", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* st8d [$m16_Ra],$m16_R0 */
  {
    NIOS_INSN_ST8D16, "st8d16", "st8d", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* wrctl $m16_Ra */
  {
    NIOS_INSN_WRCTL16, "wrctl16", "wrctl", 16,
    { 0|A(DELAY_SLOT)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* addc $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_ADDC16, "addc16", "addc", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* subc $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_SUBC16, "subc16", "subc", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* add $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_ADD16, "add16", "add", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* sub $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_SUB16, "sub16", "sub", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* addi $m16_Ra,$i5 */
  {
    NIOS_INSN_ADDI16, "addi16", "addi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* subi $m16_Ra,$i5 */
  {
    NIOS_INSN_SUBI16, "subi16", "subi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* or $m16_Ra,$Rbi5 */
  {
    NIOS_INSN_OR16, "or16", "or", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* xor $m16_Ra,$Rbi5 */
  {
    NIOS_INSN_XOR16, "xor16", "xor", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* and $m16_Ra,$Rbi5 */
  {
    NIOS_INSN_AND16, "and16", "and", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* andn $m16_Ra,$Rbi5 */
  {
    NIOS_INSN_ANDN16, "andn16", "andn", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* lsl $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_LSL16, "lsl16", "lsl", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* lsr $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_LSR16, "lsr16", "lsr", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* asr $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_ASR16, "asr16", "asr", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* lsli $m16_Ra,$i5 */
  {
    NIOS_INSN_LSLI16, "lsli16", "lsli", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* lsri $m16_Ra,$i5 */
  {
    NIOS_INSN_LSRI16, "lsri16", "lsri", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* asri $m16_Ra,$i5 */
  {
    NIOS_INSN_ASRI16, "asri16", "asri", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* not $m16_Ra */
  {
    NIOS_INSN_NOT16, "not16", "not", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* neg $m16_Ra */
  {
    NIOS_INSN_NEG16, "neg16", "neg", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* abs $m16_Ra */
  {
    NIOS_INSN_ABS16, "abs16", "abs", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* mov $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_MOV16, "mov16", "mov", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* movi $m16_Ra,$i5 */
  {
    NIOS_INSN_MOVI16, "movi16", "movi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* bgen $m16_Ra,$i5 */
  {
    NIOS_INSN_BGEN16, "bgen16", "bgen", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* cmp $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_CMP16, "cmp16", "cmp", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* cmpi $m16_Ra,$i5 */
  {
    NIOS_INSN_CMPI16, "cmpi16", "cmpi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* ext8d $m16_Ra,$m16_Rb */
  {
    NIOS_INSN_EXT8D16, "ext8d16", "ext8d", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* sext8 $m16_Ra */
  {
    NIOS_INSN_SEXT816, "sext816", "sext8", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* fill8 $m16_R0,$m16_Ra */
  {
    NIOS_INSN_FILL816, "fill816", "fill8", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* lds $m16_Ra,[$m16_sp,$i8] */
  {
    NIOS_INSN_LDS16, "lds16", "lds", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* sts [$m16_sp,$i8],$m16_Ra */
  {
    NIOS_INSN_STS16, "sts16", "sts", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* ldp $m16_Ra,[$m16_Rp,$i5] */
  {
    NIOS_INSN_LDP16, "ldp16", "ldp", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* stp [$m16_Rp,$i5],$m16_Ra */
  {
    NIOS_INSN_STP16, "stp16", "stp", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* ld $m16_Ra,[$m16_Rb] */
  {
    NIOS_INSN_LD16, "ld16", "ld", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* st [$m16_Rb],$m16_Ra */
  {
    NIOS_INSN_ST16, "st16", "st", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS16) } } } }
  },
/* trap $i6v */
  {
    NIOS_INSN_TRAP16, "trap16", "trap", 16,
    { 0|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* tret $m16_Ra */
  {
    NIOS_INSN_TRET16, "tret16", "tret", 16,
    { 0|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* save $m16_sp,$save_i8v */
  {
    NIOS_INSN_SAVE16, "save16", "save", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* restore */
  {
    NIOS_INSN_RESTORE16, "restore16", "restore", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* bsr $rel11 */
  {
    NIOS_INSN_BSR16, "bsr16", "bsr", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* bsrr $m16_Ra,$bsrr_rel6 */
  {
    NIOS_INSN_BSRR16, "bsrr16", "bsrr", 16,
    { 0|A(RELAXABLE)|A(NO_DIS)|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* jmp $m16_Ra */
  {
    NIOS_INSN_JMP16, "jmp16", "jmp", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* call $m16_Ra */
  {
    NIOS_INSN_CALL16, "call16", "call", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* jmpc [$m16_i8v] */
  {
    NIOS_INSN_JMPC16, "jmpc16", "jmpc", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* callc [$m16_i8v] */
  {
    NIOS_INSN_CALLC16, "callc16", "callc", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* skp0 $m16_Ra,$i5 */
  {
    NIOS_INSN_SKP016, "skp016", "skp0", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* skp1 $m16_Ra,$i5 */
  {
    NIOS_INSN_SKP116, "skp116", "skp1", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* skprz $m16_Ra */
  {
    NIOS_INSN_SKPRZ16, "skprz16", "skprz", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* skprnz $m16_Ra */
  {
    NIOS_INSN_SKPRNZ16, "skprnz16", "skprnz", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* skps $i4w */
  {
    NIOS_INSN_SKPS16, "skps16", "skps", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS16) } } } }
  },
/* rrc $m16_Ra */
  {
    NIOS_INSN_RRC16, "rrc16", "rrc", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* rlc $m16_Ra */
  {
    NIOS_INSN_RLC16, "rlc16", "rlc", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* rdctl $m16_Ra */
  {
    NIOS_INSN_RDCTL16, "rdctl16", "rdctl", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* usr0 $m16_Ra */
  {
    NIOS_INSN_USR016, "usr016", "usr0", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* usr1 $m16_Ra,$m16_R0 */
  {
    NIOS_INSN_USR116, "usr116", "usr1", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* usr2 $m16_Ra,$m16_R0 */
  {
    NIOS_INSN_USR216, "usr216", "usr2", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* usr3 $m16_Ra,$m16_R0 */
  {
    NIOS_INSN_USR316, "usr316", "usr3", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* usr4 $m16_Ra,$m16_R0 */
  {
    NIOS_INSN_USR416, "usr416", "usr4", 16,
    { 0, { { { (1<<MACH_NIOS16) } } } }
  },
/* sts8s [$m32_sp,$i10],$m32_R0 */
  {
    NIOS_INSN_STS8S32, "sts8s32", "sts8s", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* sts16s [$m32_sp,$i9],$m32_R0 */
  {
    NIOS_INSN_STS16S, "sts16s", "sts16s", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* movhi $m32_Ra,$i5 */
  {
    NIOS_INSN_MOVHI, "movhi", "movhi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* ext16d $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_EXT16D, "ext16d", "ext16d", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* sext16 $m32_Ra */
  {
    NIOS_INSN_SEXT16, "sext16", "sext16", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* st16d [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_ST16D, "st16d", "st16d", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* fill16 $m32_R0,$m32_Ra */
  {
    NIOS_INSN_FILL16, "fill16", "fill16", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* ext8s $m32_Ra,$i2 */
  {
    NIOS_INSN_EXT8S32, "ext8s32", "ext8s", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* st8s [$m32_Ra],$m32_R0,$i2 */
  {
    NIOS_INSN_ST8S32, "st8s32", "st8s", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* ext16s $m32_Ra,$i1 */
  {
    NIOS_INSN_EXT16S, "ext16s", "ext16s", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* st16s [$m32_Ra],$m32_R0,$i1 */
  {
    NIOS_INSN_ST16S, "st16s", "st16s", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* st8d [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_ST8D32, "st8d32", "st8d", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* wrctl $m32_Ra */
  {
    NIOS_INSN_WRCTL32, "wrctl32", "wrctl", 16,
    { 0|A(DELAY_SLOT)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* add $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_ADD32, "add32", "add", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* sub $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_SUB32, "sub32", "sub", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* addi $m32_Ra,$i5 */
  {
    NIOS_INSN_ADDI32, "addi32", "addi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* subi $m32_Ra,$i5 */
  {
    NIOS_INSN_SUBI32, "subi32", "subi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* or $m32_Ra,$Rbi5 */
  {
    NIOS_INSN_OR32, "or32", "or", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* xor $m32_Ra,$Rbi5 */
  {
    NIOS_INSN_XOR32, "xor32", "xor", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* and $m32_Ra,$Rbi5 */
  {
    NIOS_INSN_AND32, "and32", "and", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* andn $m32_Ra,$Rbi5 */
  {
    NIOS_INSN_ANDN32, "andn32", "andn", 16,
    { 0|A(DUAL_MODE)|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* lsl $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_LSL32, "lsl32", "lsl", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* lsr $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_LSR32, "lsr32", "lsr", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* asr $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_ASR32, "asr32", "asr", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* lsli $m32_Ra,$i5 */
  {
    NIOS_INSN_LSLI32, "lsli32", "lsli", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* lsri $m32_Ra,$i5 */
  {
    NIOS_INSN_LSRI32, "lsri32", "lsri", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* asri $m32_Ra,$i5 */
  {
    NIOS_INSN_ASRI32, "asri32", "asri", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* not $m32_Ra */
  {
    NIOS_INSN_NOT32, "not32", "not", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* neg $m32_Ra */
  {
    NIOS_INSN_NEG32, "neg32", "neg", 16,
    { 0, { { {(1<<MACH_NIOS32) } } } }
  },
/* abs $m32_Ra */
  {
    NIOS_INSN_ABS32, "abs32", "abs", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* mov $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_MOV32, "mov32", "mov", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* movi $m32_Ra,$i5 */
  {
    NIOS_INSN_MOVI32, "movi32", "movi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* bgen $m32_Ra,$i5 */
  {
    NIOS_INSN_BGEN32, "bgen32", "bgen", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* cmp $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_CMP32, "cmp32", "cmp", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* cmpi $m32_Ra,$i5 */
  {
    NIOS_INSN_CMPI32, "cmpi32", "cmpi", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* ext8d $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_EXT8D32, "ext8d32", "ext8d", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* sext8 $m32_Ra */
  {
    NIOS_INSN_SEXT832, "sext832", "sext8", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* fill8 $m32_R0,$m32_Ra */
  {
    NIOS_INSN_FILL832, "fill832", "fill8", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* lds $m32_Ra,[$m32_sp,$i8] */
  {
    NIOS_INSN_LDS32, "lds32", "lds", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* sts [$m32_sp,$i8],$m32_Ra */
  {
    NIOS_INSN_STS32, "sts32", "sts", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* ldp $m32_Ra,[$m32_Rp,$i5] */
  {
    NIOS_INSN_LDP32, "ldp32", "ldp", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* stp [$m32_Rp,$i5],$m32_Ra */
  {
    NIOS_INSN_STP32, "stp32", "stp", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* ld $m32_Ra,[$m32_Rb] */
  {
    NIOS_INSN_LD32, "ld32", "ld", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* st [$m32_Rb],$m32_Ra */
  {
    NIOS_INSN_ST32, "st32", "st", 16,
    { 0|A(PREFIXED_INSN), { { { (1<<MACH_NIOS32) } } } }
  },
/* trap $i6v */
  {
    NIOS_INSN_TRAP32, "trap32", "trap", 16,
    { 0|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* tret $m32_Ra */
  {
    NIOS_INSN_TRET32, "tret32", "tret", 16,
    { 0|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* save $m32_sp,$save_i8v */
  {
    NIOS_INSN_SAVE32, "save32", "save", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* restore */
  {
    NIOS_INSN_RESTORE32, "restore32", "restore", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* bsr $rel11 */
  {
    NIOS_INSN_BSR32, "bsr32", "bsr", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* bsrr $m32_Ra,$bsrr_rel6 */
  {
    NIOS_INSN_BSRR32, "bsrr32", "bsrr", 16,
    { 0|A(RELAXABLE)|A(NO_DIS)|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* jmp $m32_Ra */
  {
    NIOS_INSN_JMP32, "jmp32", "jmp", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* call $m32_Ra */
  {
    NIOS_INSN_CALL32, "call32", "call", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* jmpc [$m32_i8v] */
  {
    NIOS_INSN_JMPC32, "jmpc32", "jmpc", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* callc [$m32_i8v] */
  {
    NIOS_INSN_CALLC32, "callc32", "callc", 16,
    { 0|A(DELAY_SLOT)|A(UNCOND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* skp0 $m32_Ra,$i5 */
  {
    NIOS_INSN_SKP032, "skp032", "skp0", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* skp1 $m32_Ra,$i5 */
  {
    NIOS_INSN_SKP132, "skp132", "skp1", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* skprz $m32_Ra */
  {
    NIOS_INSN_SKPRZ32, "skprz32", "skprz", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* skprnz $m32_Ra */
  {
    NIOS_INSN_SKPRNZ32, "skprnz32", "skprnz", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* skps $i4w */
  {
    NIOS_INSN_SKPS32, "skps32", "skps", 16,
    { 0|A(SKIP_INSN)|A(COND_CTI), { { { (1<<MACH_NIOS32) } } } }
  },
/* rrc $m32_Ra */
  {
    NIOS_INSN_RRC32, "rrc32", "rrc", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* rlc $m32_Ra */
  {
    NIOS_INSN_RLC32, "rlc32", "rlc", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* rdctl $m32_Ra */
  {
    NIOS_INSN_RDCTL32, "rdctl32", "rdctl", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* pfx $i11 */
  {
    NIOS_INSN_PFX, "pfx", "pfx", 16,
    { 0|A(PREFIX), { { { (1<<MACH_BASE) } } } }
  },
/* br $rel11 */
  {
    NIOS_INSN_BR, "br", "br", 16,
    { 0|A(UNCOND_CTI)|A(DELAY_SLOT), { { { (1<<MACH_BASE) } } } }
  },
/* swap $m32_Ra */
  {
    NIOS_INSN_SWAP32, "swap32", "swap", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* mstep $m32_Ra */
  {
    NIOS_INSN_RRC32, "mstep32", "mstep", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* mul $m32_Ra */
  {
    NIOS_INSN_RRC32, "mul32", "mul", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* usr0 $m32_Ra,$m32_Rb */
  {
    NIOS_INSN_USR032, "usr032", "usr0", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* usr1 [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_USR132, "usr132", "usr1", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* usr2 [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_USR232, "usr232", "usr2", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* usr3 [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_USR332, "usr332", "usr3", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* usr4 [$m32_Ra],$m32_R0 */
  {
    NIOS_INSN_USR432, "usr432", "usr4", 16,
    { 0, { { { (1<<MACH_NIOS32) } } } }
  },
/* pfxio $i11 */
  {
    NIOS_INSN_PFXIO, "pfxio", "pfxio", 16,
    { 0|A(PREFIX), { { { (1<<MACH_BASE) } } } }
  },
};

#undef OP
#undef A

/* Initialize anything needed to be done once, before any cpu_open call.  */

static void
init_tables (void)
{
}

#ifndef opcodes_error_handler
#define opcodes_error_handler(...) \
  fprintf (stderr, __VA_ARGS__); fputc ('\n', stderr)
#endif

static const CGEN_MACH * lookup_mach_via_bfd_name (const CGEN_MACH *, const char *);
static void build_hw_table      (CGEN_CPU_TABLE *);
static void build_ifield_table  (CGEN_CPU_TABLE *);
static void build_operand_table (CGEN_CPU_TABLE *);
static void build_insn_table    (CGEN_CPU_TABLE *);
static void nios_cgen_rebuild_tables (CGEN_CPU_TABLE *);

/* Subroutine of nios_cgen_cpu_open to look up a mach via its bfd name.  */

static const CGEN_MACH *
lookup_mach_via_bfd_name (const CGEN_MACH *table, const char *name)
{
  while (table->name)
    {
      if (strcmp (name, table->bfd_name) == 0)
	return table;
      ++table;
    }
  return NULL;
}

/* Subroutine of nios_cgen_cpu_open to build the hardware table.  */

static void
build_hw_table (CGEN_CPU_TABLE *cd)
{
  int i;
  int machs = cd->machs;
  const CGEN_HW_ENTRY *init = & nios_cgen_hw_table[0];
  /* MAX_HW is only an upper bound on the number of selected entries.
     However each entry is indexed by it's enum so there can be holes in
     the table.  */
  const CGEN_HW_ENTRY **selected =
    (const CGEN_HW_ENTRY **) xmalloc (MAX_HW * sizeof (CGEN_HW_ENTRY *));

  cd->hw_table.init_entries = init;
  cd->hw_table.entry_size = sizeof (CGEN_HW_ENTRY);
  memset (selected, 0, MAX_HW * sizeof (CGEN_HW_ENTRY *));
  /* ??? For now we just use machs to determine which ones we want.  */
  for (i = 0; init[i].name != NULL; ++i)
    if (CGEN_HW_ATTR_VALUE (&init[i], CGEN_HW_MACH)
	& machs)
      selected[init[i].type] = &init[i];
  cd->hw_table.entries = selected;
  cd->hw_table.num_entries = MAX_HW;
}

/* Subroutine of nios_cgen_cpu_open to build the hardware table.  */

static void
build_ifield_table (CGEN_CPU_TABLE *cd)
{
  cd->ifld_table = & nios_cgen_ifld_table[0];
}

/* Subroutine of nios_cgen_cpu_open to build the hardware table.  */

static void
build_operand_table (CGEN_CPU_TABLE *cd)
{
  int i;
  int machs = cd->machs;
  const CGEN_OPERAND *init = & nios_cgen_operand_table[0];
  /* MAX_OPERANDS is only an upper bound on the number of selected entries.
     However each entry is indexed by it's enum so there can be holes in
     the table.  */
  const CGEN_OPERAND **selected = xmalloc (MAX_OPERANDS * sizeof (* selected));

  cd->operand_table.init_entries = init;
  cd->operand_table.entry_size = sizeof (CGEN_OPERAND);
  memset (selected, 0, MAX_OPERANDS * sizeof (CGEN_OPERAND *));
  /* ??? For now we just use mach to determine which ones we want.  */
  for (i = 0; init[i].name != NULL; ++i)
    if (CGEN_OPERAND_ATTR_VALUE (&init[i], CGEN_OPERAND_MACH)
	& machs)
      selected[init[i].type] = &init[i];
  cd->operand_table.entries = selected;
  cd->operand_table.num_entries = MAX_OPERANDS;
}

/* Subroutine of nios_cgen_cpu_open to build the hardware table.
   ??? This could leave out insns not supported by the specified mach/isa,
   but that would cause errors like "foo only supported by bar" to become
   "unknown insn", so for now we include all insns and require the app to
   do the checking later.
   ??? On the other hand, parsing of such insns may require their hardware or
   operand elements to be in the table [which they mightn't be].  */

static void
build_insn_table (CGEN_CPU_TABLE *cd)
{
  int i;
  const CGEN_IBASE *ib = & nios_cgen_insn_table[0];
  CGEN_INSN *insns = xmalloc (MAX_INSNS * sizeof (CGEN_INSN));

  memset (insns, 0, MAX_INSNS * sizeof (CGEN_INSN));
  for (i = 0; i < MAX_INSNS; ++i)
    insns[i].base = &ib[i];
  cd->insn_table.init_entries = insns;
  cd->insn_table.entry_size = sizeof (CGEN_IBASE);
  cd->insn_table.num_init_entries = MAX_INSNS;
}

/* Subroutine of nios_cgen_cpu_open to rebuild the tables.  */

static void
nios_cgen_rebuild_tables (CGEN_CPU_TABLE *cd)
{
  int i;
  CGEN_BITSET *isas = cd->isas;
  unsigned int machs = cd->machs;

  cd->int_insn_p = CGEN_INT_INSN_P;

  /* Data derived from the isa spec.  */
#define UNSET (CGEN_SIZE_UNKNOWN + 1)
  cd->default_insn_bitsize = UNSET;
  cd->base_insn_bitsize = UNSET;
  cd->min_insn_bitsize = 65535; /* Some ridiculously big number.  */
  cd->max_insn_bitsize = 0;
  for (i = 0; i < MAX_ISAS; ++i)
    if (cgen_bitset_contains (isas, i))
      {
	const CGEN_ISA *isa = & nios_cgen_isa_table[i];

	/* Default insn sizes of all selected isas must be
	   equal or we set the result to 0, meaning "unknown".  */
	if (cd->default_insn_bitsize == UNSET)
	  cd->default_insn_bitsize = isa->default_insn_bitsize;
	else if (isa->default_insn_bitsize == cd->default_insn_bitsize)
	  ; /* This is ok.  */
	else
	  cd->default_insn_bitsize = CGEN_SIZE_UNKNOWN;

	/* Base insn sizes of all selected isas must be equal
	   or we set the result to 0, meaning "unknown".  */
	if (cd->base_insn_bitsize == UNSET)
	  cd->base_insn_bitsize = isa->base_insn_bitsize;
	else if (isa->base_insn_bitsize == cd->base_insn_bitsize)
	  ; /* This is ok.  */
	else
	  cd->base_insn_bitsize = CGEN_SIZE_UNKNOWN;

	/* Set min,max insn sizes.  */
	if (isa->min_insn_bitsize < cd->min_insn_bitsize)
	  cd->min_insn_bitsize = isa->min_insn_bitsize;
	if (isa->max_insn_bitsize > cd->max_insn_bitsize)
	  cd->max_insn_bitsize = isa->max_insn_bitsize;
      }

  /* Data derived from the mach spec.  */
  for (i = 0; i < MAX_MACHS; ++i)
    if (((1 << i) & machs) != 0)
      {
	const CGEN_MACH *mach = & nios_cgen_mach_table[i];

	if (mach->insn_chunk_bitsize != 0)
	{
	  if (cd->insn_chunk_bitsize != 0 && cd->insn_chunk_bitsize != mach->insn_chunk_bitsize)
	    {
	      opcodes_error_handler
		(/* xgettext:c-format */
		 _("internal error: nios_cgen_rebuild_tables: "
		   "conflicting insn-chunk-bitsize values: `%d' vs. `%d'"),
		 cd->insn_chunk_bitsize, mach->insn_chunk_bitsize);
	      abort ();
	    }

	  cd->insn_chunk_bitsize = mach->insn_chunk_bitsize;
	}
      }

  /* Determine which hw elements are used by MACH.  */
  build_hw_table (cd);

  /* Build the ifield table.  */
  build_ifield_table (cd);

  /* Determine which operands are used by MACH/ISA.  */
  build_operand_table (cd);

  /* Build the instruction table.  */
  build_insn_table (cd);
}

/* Initialize a cpu table and return a descriptor.
   It's much like opening a file, and must be the first function called.
   The arguments are a set of (type/value) pairs, terminated with
   CGEN_CPU_OPEN_END.

   Currently supported values:
   CGEN_CPU_OPEN_ISAS:    bitmap of values in enum isa_attr
   CGEN_CPU_OPEN_MACHS:   bitmap of values in enum mach_attr
   CGEN_CPU_OPEN_BFDMACH: specify 1 mach using bfd name
   CGEN_CPU_OPEN_ENDIAN:  specify endian choice
   CGEN_CPU_OPEN_END:     terminates arguments

   ??? Simultaneous multiple isas might not make sense, but it's not (yet)
   precluded.  */

CGEN_CPU_DESC
nios_cgen_cpu_open (enum cgen_cpu_open_arg arg_type, ...)
{
  CGEN_CPU_TABLE *cd = (CGEN_CPU_TABLE *) xmalloc (sizeof (CGEN_CPU_TABLE));
  static int init_p;
  CGEN_BITSET *isas = 0;  /* 0 = "unspecified" */
  unsigned int machs = 0; /* 0 = "unspecified" */
  enum cgen_endian endian = CGEN_ENDIAN_UNKNOWN;
  va_list ap;

  if (! init_p)
    {
      init_tables ();
      init_p = 1;
    }

  memset (cd, 0, sizeof (*cd));

  va_start (ap, arg_type);
  while (arg_type != CGEN_CPU_OPEN_END)
    {
      switch (arg_type)
	{
	case CGEN_CPU_OPEN_ISAS :
	  isas = va_arg (ap, CGEN_BITSET *);
	  break;
	case CGEN_CPU_OPEN_MACHS :
	  machs = va_arg (ap, unsigned int);
	  break;
	case CGEN_CPU_OPEN_BFDMACH :
	  {
	    const char *name = va_arg (ap, const char *);
	    const CGEN_MACH *mach =
	      lookup_mach_via_bfd_name (nios_cgen_mach_table, name);

	    if (mach != NULL)
	      machs |= 1 << mach->num;
	    break;
	  }
	case CGEN_CPU_OPEN_ENDIAN :
	  endian = va_arg (ap, enum cgen_endian);
	  break;
	default :
	  opcodes_error_handler
	    (/* xgettext:c-format */
	     _("internal error: nios_cgen_cpu_open: "
	       "unsupported argument `%d'"),
	     arg_type);
	  abort (); /* ??? return NULL? */
	}
      arg_type = va_arg (ap, enum cgen_cpu_open_arg);
    }
  va_end (ap);

  /* Mach unspecified means "all".  */
  if (machs == 0)
    machs = (1 << MAX_MACHS) - 1;
  /* Base mach is always selected.  */
  machs |= 1;
  if (endian == CGEN_ENDIAN_UNKNOWN)
    {
      /* ??? If target has only one, could have a default.  */
      opcodes_error_handler
	(/* xgettext:c-format */
	 _("internal error: nios_cgen_cpu_open: no endianness specified"));
      abort ();
    }

  cd->isas = cgen_bitset_copy (isas);
  cd->machs = machs;
  cd->endian = endian;
  /* FIXME: for the sparc case we can determine insn-endianness statically.
     The worry here is where both data and insn endian can be independently
     chosen, in which case this function will need another argument.
     Actually, will want to allow for more arguments in the future anyway.  */
  cd->insn_endian = endian;

  /* Table (re)builder.  */
  cd->rebuild_tables = nios_cgen_rebuild_tables;
  nios_cgen_rebuild_tables (cd);

  /* Default to not allowing signed overflow.  */
  cd->signed_overflow_ok_p = 0;

  return (CGEN_CPU_DESC) cd;
}

/* Cover fn to nios_cgen_cpu_open to handle the simple case of 1 isa, 1 mach.
   MACH_NAME is the bfd name of the mach.  */

CGEN_CPU_DESC
nios_cgen_cpu_open_1 (const char *mach_name, enum cgen_endian endian)
{
  return nios_cgen_cpu_open (CGEN_CPU_OPEN_BFDMACH, mach_name,
			       CGEN_CPU_OPEN_ENDIAN, endian,
			       CGEN_CPU_OPEN_END);
}

/* Close a cpu table.
   ??? This can live in a machine independent file, but there's currently
   no place to put this file (there's no libcgen).  libopcodes is the wrong
   place as some simulator ports use this but they don't use libopcodes.  */

void
nios_cgen_cpu_close (CGEN_CPU_DESC cd)
{

#if 0
  const CGEN_INSN *insns;
  unsigned int i;
  if (cd->macro_insn_table.init_entries)
    {
      insns = cd->macro_insn_table.init_entries;
      for (i = 0; i < cd->macro_insn_table.num_init_entries; ++i, ++insns)
	if (CGEN_INSN_RX ((insns)))
	  regfree (CGEN_INSN_RX (insns));
    }

  if (cd->insn_table.init_entries)
    {
      insns = cd->insn_table.init_entries;
      for (i = 0; i < cd->insn_table.num_init_entries; ++i, ++insns)
	if (CGEN_INSN_RX (insns))
	  regfree (CGEN_INSN_RX (insns));
    }
#endif

  if (cd->macro_insn_table.init_entries)
    free ((CGEN_INSN *) cd->macro_insn_table.init_entries);

  if (cd->insn_table.init_entries)
    free ((CGEN_INSN *) cd->insn_table.init_entries);

  if (cd->hw_table.entries)
    free ((CGEN_HW_ENTRY *) cd->hw_table.entries);

  if (cd->operand_table.entries)
    free ((CGEN_HW_ENTRY *) cd->operand_table.entries);

  free (cd);
}

