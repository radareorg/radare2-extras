/* Instruction opcode header for nios.

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

#ifndef NIOS_OPC_H
#define NIOS_OPC_H

#ifdef __cplusplus
extern "C" {
#endif

/* -- opc.h */

#undef CGEN_DIS_HASH_SIZE
#define CGEN_DIS_HASH_SIZE 65
#undef CGEN_DIS_HASH
#define CGEN_DIS_HASH(buffer, value) (((unsigned char *) (buffer))[1] >> 5)

/* condition code masks for SKPS instruction */

#define CC_C       0x0
#define CC_NC      0x1
#define CC_Z       0x2
#define CC_NZ      0x3
#define CC_MI      0x4
#define CC_PL      0x5
#define CC_GE      0x6
#define CC_LT      0x7
#define CC_LE      0x8
#define CC_GT      0x9
#define CC_V       0xa
#define CC_NV      0xb
#define CC_LS      0xc
#define CC_HI      0xd
#define CC_MAX     CC_HI

/* following activates check beyond hashing since m16 and m32 instructions
 * hash identically, but have different descriptions */
#define CGEN_VALIDATE_INSN_SUPPORTED

/* following allows reason codes to be output when assembler errors occur */
#define CGEN_VERBOSE_ASSEMBLER_ERRORS

/* Special check to ensure that instruction exists for given machine */
ATTRIBUTE_UNUSED static int
nios_cgen_insn_supported (CGEN_CPU_DESC cd, const CGEN_INSN *insn)
{
  int machs = cd->machs;

  return ((CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_MACH) & machs) != 0);
}

/* values to signal between parse routines and md_assemble */
extern int nios_parsed_i11;
extern int nios_Rbi5;

/* values of nios_Rbi5 to help catch Rbi5 syntax errors */
#define NIOS_RBI5_REGISTER  1
#define NIOS_RBI5_IMMEDIATE 2

/* -- */
/* Enum declaration for nios instruction types.  */
typedef enum cgen_insn_type {
  NIOS_INSN_INVALID, NIOS_INSN_EXT8S16, NIOS_INSN_ST8S16, NIOS_INSN_STS8S16
 , NIOS_INSN_ST8D16, NIOS_INSN_WRCTL16, NIOS_INSN_ADDC16, NIOS_INSN_SUBC16
 , NIOS_INSN_ADD16, NIOS_INSN_SUB16, NIOS_INSN_ADDI16, NIOS_INSN_SUBI16
 , NIOS_INSN_OR16, NIOS_INSN_XOR16, NIOS_INSN_AND16, NIOS_INSN_ANDN16
 , NIOS_INSN_LSL16, NIOS_INSN_LSR16, NIOS_INSN_ASR16, NIOS_INSN_LSLI16
 , NIOS_INSN_LSRI16, NIOS_INSN_ASRI16, NIOS_INSN_NOT16, NIOS_INSN_NEG16
 , NIOS_INSN_ABS16, NIOS_INSN_MOV16, NIOS_INSN_MOVI16, NIOS_INSN_BGEN16
 , NIOS_INSN_CMP16, NIOS_INSN_CMPI16,                  NIOS_INSN_EXT8D16
 , NIOS_INSN_SEXT816, NIOS_INSN_FILL816, NIOS_INSN_LDS16, NIOS_INSN_STS16
 , NIOS_INSN_LDP16, NIOS_INSN_STP16, NIOS_INSN_LD16, NIOS_INSN_ST16
 , NIOS_INSN_TRAP16, NIOS_INSN_TRET16, NIOS_INSN_SAVE16, NIOS_INSN_RESTORE16
 , NIOS_INSN_BSR16, NIOS_INSN_BSRR16, NIOS_INSN_JMP16, NIOS_INSN_CALL16
 , NIOS_INSN_JMPC16, NIOS_INSN_CALLC16, NIOS_INSN_SKP016, NIOS_INSN_SKP116
 , NIOS_INSN_SKPRZ16, NIOS_INSN_SKPRNZ16, NIOS_INSN_SKPS16, NIOS_INSN_RRC16
 , NIOS_INSN_RLC16, NIOS_INSN_RDCTL16, NIOS_INSN_USR016, NIOS_INSN_USR116
 , NIOS_INSN_USR216, NIOS_INSN_USR316, NIOS_INSN_USR416, NIOS_INSN_STS8S32
 , NIOS_INSN_STS16S, NIOS_INSN_MOVHI, NIOS_INSN_EXT16D, NIOS_INSN_SEXT16
 , NIOS_INSN_ST16D, NIOS_INSN_FILL16, NIOS_INSN_EXT8S32, NIOS_INSN_ST8S32
 , NIOS_INSN_EXT16S, NIOS_INSN_ST16S, NIOS_INSN_ST8D32, NIOS_INSN_WRCTL32 
 , NIOS_INSN_ADD32, NIOS_INSN_SUB32, NIOS_INSN_ADDI32, NIOS_INSN_SUBI32
 , NIOS_INSN_OR32, NIOS_INSN_XOR32, NIOS_INSN_AND32, NIOS_INSN_ANDN32
 , NIOS_INSN_LSL32, NIOS_INSN_LSR32, NIOS_INSN_ASR32, NIOS_INSN_LSLI32
 , NIOS_INSN_LSRI32, NIOS_INSN_ASRI32, NIOS_INSN_NOT32, NIOS_INSN_NEG32
 , NIOS_INSN_ABS32, NIOS_INSN_MOV32, NIOS_INSN_MOVI32, NIOS_INSN_BGEN32
 , NIOS_INSN_CMP32, NIOS_INSN_CMPI32,                  NIOS_INSN_EXT8D32
 , NIOS_INSN_SEXT832, NIOS_INSN_FILL832, NIOS_INSN_LDS32, NIOS_INSN_STS32
 , NIOS_INSN_LDP32, NIOS_INSN_STP32, NIOS_INSN_LD32, NIOS_INSN_ST32
 , NIOS_INSN_TRAP32, NIOS_INSN_TRET32, NIOS_INSN_SAVE32, NIOS_INSN_RESTORE32
 , NIOS_INSN_BSR32, NIOS_INSN_BSRR32, NIOS_INSN_JMP32, NIOS_INSN_CALL32
 , NIOS_INSN_JMPC32, NIOS_INSN_CALLC32, NIOS_INSN_SKP032, NIOS_INSN_SKP132
 , NIOS_INSN_SKPRZ32, NIOS_INSN_SKPRNZ32, NIOS_INSN_SKPS32, NIOS_INSN_RRC32
 , NIOS_INSN_RLC32, NIOS_INSN_RDCTL32, NIOS_INSN_PFX, NIOS_INSN_BR
 , NIOS_INSN_SWAP32, NIOS_INSN_MSTEP32, NIOS_INSN_MUL32, NIOS_INSN_USR032
 , NIOS_INSN_USR132, NIOS_INSN_USR232, NIOS_INSN_USR332, NIOS_INSN_USR432
 , NIOS_INSN_PFXIO, NIOS_INSN_MAX
} CGEN_INSN_TYPE;

/* Index of `invalid' insn place holder.  */
#define CGEN_INSN_INVALID NIOS_INSN_INVALID

/* Total number of insns in table.  */
#define MAX_INSNS ((int) NIOS_INSN_MAX)

/* This struct records data prior to insertion or after extraction.  */
struct cgen_fields
{
  int length;
  long f_nil;
  long f_anyof;
  long f_op6;
  long f_op3;
  long f_op4;
  long f_op5;
  long f_op5_hi;
  long f_op8;
  long f_op9;
  long f_op11;
  long f_Ra;
  long f_Rb;
  long f_Rbi5;
  long f_Rz;
  long f_Rp;
  long f_CTLc;
  long f_i2;
  long f_i4w;
  long f_x1;
  long f_o1;
  long f_o2;
  long f_i5;
  long f_i6v;
  long f_i8;
  long f_i8v;
  long f_i9;
  long f_i10;
  long f_i11;
  long f_i6_rel_h;
  long f_i6_rel_w;
  long f_bsrr_i6_rel;
  long f_i8v_rel_h;
  long f_i8v_rel_w;
  long f_i11_rel;
  long f_i1;
};

#define CGEN_INIT_PARSE(od) \
{\
}
#define CGEN_INIT_INSERT(od) \
{\
}
#define CGEN_INIT_EXTRACT(od) \
{\
}
#define CGEN_INIT_PRINT(od) \
{\
}


   #ifdef __cplusplus
   }
   #endif

#endif /* NIOS_OPC_H */
