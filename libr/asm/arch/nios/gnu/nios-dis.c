/* Disassembler interface for targets using CGEN. -*- C -*-
   CGEN: Cpu tools GENerator

THIS FILE IS MACHINE GENERATED WITH CGEN.
- the resultant file is machine generated, cgen-dis.in isn't

Copyright (C) 1996, 1997, 1998, 1999 Free Software Foundation, Inc.

This file is part of the GNU Binutils and GDB, the GNU debugger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* ??? Eventually more and more of this stuff can go to cpu-independent files.
   Keep that in mind.  */

#include "sysdep.h"
#include <stdio.h>
#include "ansidecl.h"
#include "dis-asm.h"
#include "bfd.h"
#include "symcat.h"
#include "nios-desc.h"
#include "nios-opc.h"
#include "opintl.h"

/* Default text to print if an instruction isn't recognized.  */
#define UNKNOWN_INSN_MSG _("*unknown*")

static void print_normal
     PARAMS ((CGEN_CPU_DESC, PTR, long, unsigned int, bfd_vma, int));
static void print_address
     PARAMS ((CGEN_CPU_DESC, PTR, bfd_vma, unsigned int, bfd_vma, int));
static void print_keyword
     PARAMS ((CGEN_CPU_DESC, PTR, CGEN_KEYWORD *, long, unsigned int));
static void print_insn_normal
     PARAMS ((CGEN_CPU_DESC, PTR, const CGEN_INSN *, CGEN_FIELDS *,
	      bfd_vma, int));
static int print_insn PARAMS ((CGEN_CPU_DESC, bfd_vma,
			       disassemble_info *, char *, int));
static int default_print_insn
     PARAMS ((CGEN_CPU_DESC, bfd_vma, disassemble_info *));

/* -- disassembler routines inserted here */

/* -- dis.c */

/* Include "%hi(foo) in output.  */
      
static void
print_Rbi5 (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  int status;
  char buf[2];
  unsigned long insn_value;
  const CGEN_INSN_LIST *insn_list;

  disassemble_info *info = (disassemble_info *) dis_info;

  /* look at previous instruction, if possible, to see if it is PFX */
  if (pc > 0)
    {
      status = (*info->read_memory_func) (pc - 2, buf, 2, info);  
      if (status != 0)
	{
	  print_keyword (cd, info, & nios_cgen_opval_gr_names, value, 0);
	  return;
	}
      insn_value = info->endian == BFD_ENDIAN_BIG ? bfd_getb16 (buf) : bfd_getl16 (buf);
      insn_list = CGEN_DIS_LOOKUP_INSN (cd, buf, insn_value);
      while (insn_list != NULL)
	{
	  const CGEN_INSN *insn = insn_list->insn;

	  /* Basic bit mask must be correct.  */
	  /* ??? May wish to allow target to defer this check until the extract
	     handler.  */
	  if ((insn_value & CGEN_INSN_BASE_MASK (insn))
	      == CGEN_INSN_BASE_VALUE (insn))
	    {
	      if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_PREFIX))
		(*info->fprintf_func) (info->stream, "0x%x", value);
	      else
		print_keyword (cd, info, & nios_cgen_opval_gr_names, value, 0);
	      return;
	    }
	  insn_list = CGEN_DIS_NEXT_INSN (insn_list);
	}
    }
  print_keyword (cd, info, & nios_cgen_opval_gr_names, value, 0);
}

static void
print_i11 (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;
  (*info->fprintf_func) (info->stream, "%%hi(0x%lx)", value << 5);
}

static void
print_r0 (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;
  (*info->fprintf_func) (info->stream, "%g0");
}

static void
print_i16 (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;
  (*info->fprintf_func) (info->stream, "#0x%hx)", (short)value);
}

static void
print_i32 (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;
  (*info->fprintf_func) (info->stream, "#0x%lx)", value);
}

static void
print_i4w (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  char *str;
  disassemble_info *info = (disassemble_info *) dis_info;
  switch (value)
    {
    case CC_Z:
      str = "cc_eq";
      break;
    case CC_NZ:
      str = "cc_ne";
      break;
    case CC_C:
      str = "cc_c";
      break;
    case CC_NC:
      str = "cc_nc";
      break;
    case CC_V:
      str = "cc_v";
      break;
    case CC_NV:
      str = "cc_nv";
      break;
    case CC_GT:
      str = "cc_gt";
      break;
    case CC_GE:
      str = "cc_ge";
      break;
    case CC_LT:
      str = "cc_lt";
      break;
    case CC_LE:
      str = "cc_le";
      break;
    case CC_LS:
      str = "cc_ls";
      break;
    case CC_HI:
      str = "cc_hi";
      break;
    case CC_PL:
      str = "cc_pl";
      break;
    case CC_MI:
      str = "cc_mi";
      break;
    }

  if (str != NULL)
    (*info->fprintf_func) (info->stream, "%s", str);
  else
    (*info->fprintf_func) (info->stream, "0x%x", value);
}

/* -- */

/* Main entry point for printing operands.
   XINFO is a `void *' and not a `disassemble_info *' to not put a requirement
   of dis-asm.h on cgen.h.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `print_insn_normal', but keeping it
   separate makes clear the interface between `print_insn_normal' and each of
   the handlers.
*/

void
nios_cgen_print_operand (cd, opindex, xinfo, fields, attrs, pc, length)
     CGEN_CPU_DESC cd;
     int opindex;
     PTR xinfo;
     CGEN_FIELDS *fields;
     void const *attrs;
     bfd_vma pc;
     int length;
{
 disassemble_info *info = (disassemble_info *) xinfo;

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      print_normal (cd, info, fields->f_CTLc, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_RBI5 :
      print_Rbi5 (cd, info, fields->f_Rbi5, 0, pc, length);
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      print_address (cd, info, fields->f_bsrr_i6_rel, 0|(1<<CGEN_OPERAND_RELAX)|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_I1 :
      print_normal (cd, info, fields->f_i1, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I10 :
      print_normal (cd, info, fields->f_i10, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I11 :
      print_i11 (cd, info, fields->f_i11, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I2 :
      print_normal (cd, info, fields->f_i2, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I4W :
      print_i4w (cd, info, fields->f_i4w, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I4WN :
      print_i4w (cd, info, fields->f_i4w, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I5 :
      print_normal (cd, info, fields->f_i5, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I6V :
      print_normal (cd, info, fields->f_i6v, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I8 :
      print_normal (cd, info, fields->f_i8, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I8V :
      print_normal (cd, info, fields->f_i8v, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_I9 :
      print_normal (cd, info, fields->f_i9, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_M16_R0 :
      print_keyword (cd, info, & nios_cgen_opval_h_m16_gr0, 0, 0);
      break;
    case NIOS_OPERAND_M16_RA :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Ra, 0);
      break;
    case NIOS_OPERAND_M16_RB :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Rb, 0);
      break;
    case NIOS_OPERAND_M16_RP :
      print_keyword (cd, info, & nios_cgen_opval_bp_names, fields->f_Rp, 0);
      break;
    case NIOS_OPERAND_M16_RZ :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Rz, 0);
      break;
    case NIOS_OPERAND_M16_I6 :
      print_address (cd, info, fields->f_i6_rel_h, 0|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_M16_I8V :
      print_address (cd, info, fields->f_i8v_rel_h, 0|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_M16_SP :
      print_keyword (cd, info, & nios_cgen_opval_h_m16_sp, 0, 0);
      break;
    case NIOS_OPERAND_M32_R0 :
      print_keyword (cd, info, & nios_cgen_opval_gr0_name, 0, 0);
      break;
    case NIOS_OPERAND_M32_RA :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Ra, 0);
      break;
    case NIOS_OPERAND_M32_RB :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Rb, 0);
      break;
    case NIOS_OPERAND_M32_RP :
      print_keyword (cd, info, & nios_cgen_opval_bp_names, fields->f_Rp, 0);
      break;
    case NIOS_OPERAND_M32_RZ :
      print_keyword (cd, info, & nios_cgen_opval_gr_names, fields->f_Rz, 0);
      break;
    case NIOS_OPERAND_M32_I6 :
      print_address (cd, info, fields->f_i6_rel_w, 0|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_M32_I8V :
      print_address (cd, info, fields->f_i8v_rel_w, 0|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_M32_SP :
      print_keyword (cd, info, & nios_cgen_opval_h_m32_sp, 0, 0);
      break;
    case NIOS_OPERAND_O1 :
      print_normal (cd, info, fields->f_o1, 0, pc, length);
      break;
    case NIOS_OPERAND_O2 :
      print_normal (cd, info, fields->f_o2, 0, pc, length);
      break;
    case NIOS_OPERAND_REL11 :
      print_address (cd, info, fields->f_i11_rel, 0|(1<<CGEN_OPERAND_PCREL_ADDR), pc, length);
      break;
    case NIOS_OPERAND_SAVE_I8V :
      print_normal (cd, info, fields->f_i8v, 0|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_SI11 :
      print_normal (cd, info, fields->f_i11, 0|(1<<CGEN_OPERAND_SIGNED)|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_SI5 :
      print_normal (cd, info, fields->f_i5, 0|(1<<CGEN_OPERAND_SIGNED)|(1<<CGEN_OPERAND_HASH_PREFIX), pc, length);
      break;
    case NIOS_OPERAND_X1 :
      print_normal (cd, info, fields->f_x1, 0, pc, length);
      break;
    case NIOS_OPERAND_XRA :
      print_normal (cd, info, fields->f_Ra, 0, pc, length);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while printing insn.\n"),
	       opindex);
    abort ();
  }
}

cgen_print_fn * const nios_cgen_print_handlers[] = 
{
  print_insn_normal,
};


void
nios_cgen_init_dis (cd)
     CGEN_CPU_DESC cd;
{
  nios_cgen_init_opcode_table (cd);
  nios_cgen_init_ibld_table (cd);
  cd->print_handlers = & nios_cgen_print_handlers[0];
  cd->print_operand = nios_cgen_print_operand;
}


/* Default print handler.  */

static void
print_normal (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     long value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;

#ifdef CGEN_PRINT_NORMAL
  CGEN_PRINT_NORMAL (cd, info, value, attrs, pc, length);
#endif

  /* Print the operand as directed by the attributes.  */
  if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_SEM_ONLY))
    ; /* nothing to do */
  else if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_SIGNED))
    (*info->fprintf_func) (info->stream, "%ld", value);
  else
    (*info->fprintf_func) (info->stream, "0x%lx", value);
}

/* Default address handler.  */

static void
print_address (cd, dis_info, value, attrs, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     bfd_vma value;
     unsigned int attrs;
     bfd_vma pc;
     int length;
{
  disassemble_info *info = (disassemble_info *) dis_info;

#ifdef CGEN_PRINT_ADDRESS
  CGEN_PRINT_ADDRESS (cd, info, value, attrs, pc, length);
#endif

  /* Print the operand as directed by the attributes.  */
  if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_SEM_ONLY))
    ; /* nothing to do */
  else if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_PCREL_ADDR))
    (*info->print_address_func) (value, info);
  else if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_ABS_ADDR))
    (*info->print_address_func) (value, info);
  else if (CGEN_BOOL_ATTR (attrs, CGEN_OPERAND_SIGNED))
    (*info->fprintf_func) (info->stream, "%ld", (long) value);
  else
    (*info->fprintf_func) (info->stream, "0x%lx", (long) value);
}

/* Keyword print handler.  */

static void
print_keyword (cd, dis_info, keyword_table, value, attrs)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     CGEN_KEYWORD *keyword_table;
     long value;
     unsigned int attrs;
{
  disassemble_info *info = (disassemble_info *) dis_info;
  const CGEN_KEYWORD_ENTRY *ke;

  ke = cgen_keyword_lookup_value (keyword_table, value);
  if (ke != NULL)
    (*info->fprintf_func) (info->stream, "%s", ke->name);
  else
    (*info->fprintf_func) (info->stream, "???");
}

/* Default insn printer.

   DIS_INFO is defined as `PTR' so the disassembler needn't know anything
   about disassemble_info.  */

static void
print_insn_normal (cd, dis_info, insn, fields, pc, length)
     CGEN_CPU_DESC cd;
     PTR dis_info;
     const CGEN_INSN *insn;
     CGEN_FIELDS *fields;
     bfd_vma pc;
     int length;
{
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  disassemble_info *info = (disassemble_info *) dis_info;
  const unsigned char *syn;

  CGEN_INIT_PRINT (cd);

  for (syn = CGEN_SYNTAX_STRING (syntax); *syn; ++syn)
    {
      if (CGEN_SYNTAX_MNEMONIC_P (*syn))
	{
	  (*info->fprintf_func) (info->stream, "%s", CGEN_INSN_MNEMONIC (insn));
	  continue;
	}
      if (CGEN_SYNTAX_CHAR_P (*syn))
	{
	  (*info->fprintf_func) (info->stream, "%c", CGEN_SYNTAX_CHAR (*syn));
	  continue;
	}

      /* We have an operand.  */
      nios_cgen_print_operand (cd, CGEN_SYNTAX_FIELD (*syn), info,
				 fields, CGEN_INSN_ATTRS (insn), pc, length);
    }
}

/* Utility to print an insn.
   BUF is the base part of the insn, target byte order, BUFLEN bytes long.
   The result is the size of the insn in bytes or zero for an unknown insn
   or -1 if an error occurs fetching data (memory_error_func will have
   been called).  */

static int
print_insn (cd, pc, info, buf, buflen)
     CGEN_CPU_DESC cd;
     bfd_vma pc;
     disassemble_info *info;
     char *buf;
     int buflen;
{
  unsigned long insn_value;
  const CGEN_INSN_LIST *insn_list;
  CGEN_EXTRACT_INFO ex_info;

  ex_info.dis_info = info;
  ex_info.valid = (1 << (cd->base_insn_bitsize / 8)) - 1;
  ex_info.insn_bytes = buf;

  switch (buflen)
    {
    case 1:
      insn_value = buf[0];
      break;
    case 2:
      insn_value = info->endian == BFD_ENDIAN_BIG ? bfd_getb16 (buf) : bfd_getl16 (buf);
      break;
    case 4:
      insn_value = info->endian == BFD_ENDIAN_BIG ? bfd_getb32 (buf) : bfd_getl32 (buf);
      break;
    default:
      abort ();
    }

  /* The instructions are stored in hash lists.
     Pick the first one and keep trying until we find the right one.  */

  insn_list = CGEN_DIS_LOOKUP_INSN (cd, buf, insn_value);
  while (insn_list != NULL)
    {
      const CGEN_INSN *insn = insn_list->insn;
      CGEN_FIELDS fields;
      int length;

#ifdef CGEN_VALIDATE_INSN_SUPPORTED 
      /* not needed as insn shouldn't be in hash lists if not supported */
      /* Supported by this cpu?  */
      if (! nios_cgen_insn_supported (cd, insn))
        {
          insn_list = CGEN_DIS_NEXT_INSN (insn_list);
	  continue;
        }
#endif

      /* Basic bit mask must be correct.  */
      /* ??? May wish to allow target to defer this check until the extract
	 handler.  */
      if ((insn_value & CGEN_INSN_BASE_MASK (insn))
	  == CGEN_INSN_BASE_VALUE (insn))
	{
	  /* Printing is handled in two passes.  The first pass parses the
	     machine insn and extracts the fields.  The second pass prints
	     them.  */

	  length = CGEN_EXTRACT_FN (cd, insn)
	    (cd, insn, &ex_info, insn_value, &fields, pc);
	  /* length < 0 -> error */
	  if (length < 0)
	    return length;
	  if (length > 0)
	    {
	      CGEN_PRINT_FN (cd, insn) (cd, info, insn, &fields, pc, length);
	      /* length is in bits, result is in bytes */
	      return length / 8;
	    }
	}

      insn_list = CGEN_DIS_NEXT_INSN (insn_list);
    }

  return 0;
}

/* Default value for CGEN_PRINT_INSN.
   The result is the size of the insn in bytes or zero for an unknown insn
   or -1 if an error occured fetching bytes.  */

#ifndef CGEN_PRINT_INSN
#define CGEN_PRINT_INSN default_print_insn
#endif

static int
default_print_insn (cd, pc, info)
     CGEN_CPU_DESC cd;
     bfd_vma pc;
     disassemble_info *info;
{
  char buf[CGEN_MAX_INSN_SIZE];
  int status;

  /* Read the base part of the insn.  */

  status = (*info->read_memory_func) (pc, buf, cd->base_insn_bitsize / 8, info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, pc, info);
      return -1;
    }

  return print_insn (cd, pc, info, buf, cd->base_insn_bitsize / 8);
}

/* Main entry point.
   Print one instruction from PC on INFO->STREAM.
   Return the size of the instruction (in bytes).  */

int
print_insn_nios (pc, info)
     bfd_vma pc;
     disassemble_info *info;
{
  static CGEN_CPU_DESC cd = 0;
  static prev_isa,prev_mach,prev_endian;
  int length;
  int isa,mach;
  int endian = (info->endian == BFD_ENDIAN_BIG
		? CGEN_ENDIAN_BIG
		: CGEN_ENDIAN_LITTLE);
  enum bfd_architecture arch;

  /* ??? gdb will set mach but leave the architecture as "unknown" */
#ifndef CGEN_BFD_ARCH
#define CGEN_BFD_ARCH bfd_arch_nios
#endif
  arch = info->arch;
  if (arch == bfd_arch_unknown)
    arch = CGEN_BFD_ARCH;
      
  /* There's no standard way to compute the isa number (e.g. for arm thumb)
     so we leave it to the target.  */
#ifdef CGEN_COMPUTE_ISA
  isa = CGEN_COMPUTE_ISA (info);
#else
  isa = 0;
#endif

  mach = info->mach;

  /* If we've switched cpu's, close the current table and open a new one.  */
  if (cd
      && (isa != prev_isa
	  || mach != prev_mach
	  || endian != prev_endian))
    {
      nios_cgen_cpu_close (cd);
      cd = 0;
    }

  /* If we haven't initialized yet, initialize the opcode table.  */
  if (! cd)
    {
      const bfd_arch_info_type *arch_type = bfd_lookup_arch (arch, mach);
      const char *mach_name;

      if (!arch_type)
	abort ();
      mach_name = arch_type->printable_name;

      prev_isa = isa;
      prev_mach = mach;
      prev_endian = endian;
      cd = nios_cgen_cpu_open (CGEN_CPU_OPEN_ISAS, prev_isa,
				 CGEN_CPU_OPEN_BFDMACH, mach_name,
				 CGEN_CPU_OPEN_ENDIAN, prev_endian,
				 CGEN_CPU_OPEN_END);
      if (!cd)
	abort ();
      nios_cgen_init_dis (cd);
    }

  /* We try to have as much common code as possible.
     But at this point some targets need to take over.  */
  /* ??? Some targets may need a hook elsewhere.  Try to avoid this,
     but if not possible try to move this hook elsewhere rather than
     have two hooks.  */
  length = CGEN_PRINT_INSN (cd, pc, info);
  if (length > 0)
    return length;
  if (length < 0)
    return -1;

  (*info->fprintf_func) (info->stream, UNKNOWN_INSN_MSG);
  return cd->default_insn_bitsize / 8;
}
