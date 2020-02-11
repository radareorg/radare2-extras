/* Assembler interface for targets using CGEN. -*- C -*-
   CGEN: Cpu tools GENerator

   THIS FILE IS MACHINE GENERATED WITH CGEN.
   - the resultant file is machine generated, cgen-asm.in isn't

   Copyright (C) 1996-2018 Free Software Foundation, Inc.

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */


/* ??? Eventually more and more of this stuff can go to cpu-independent files.
   Keep that in mind.  */

#include "sysdep.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ansidecl.h"
//#include "bfd.h"
#include "mybfd.h"
#include "symcat.h"
#include "nios-desc.h"
#include "nios-opc.h"
#include "opintl.h"
#include "xregex.h"
#include "libiberty.h"
#include "safe-ctype.h"

#undef  min
#define min(a,b) ((a) < (b) ? (a) : (b))
#undef  max
#define max(a,b) ((a) > (b) ? (a) : (b))

static const char * parse_insn_normal
  (CGEN_CPU_DESC, const CGEN_INSN *, const char **, CGEN_FIELDS *);

/* -- assembler routines inserted here.  */

/* -- asm.c */
/* Handle %lo(), %xlo().  */

int nios_parsed_i11 = 0;
int nios_Rbi5 = 0;

/* The following is an internal routine to allow @h values to specify offsets.
   The routine creates a temporary buffer with the string "sans" the @h specifier.
   This allows the cgen_parse_address routine to correctly set any desired offset. */
static const char *
parse_h_address (CGEN_CPU_DESC cd, const char **strp, char *at_h_pos, int opindex, int opinfo, enum cgen_parse_operand_result *resultp, bfd_vma *valuep)
{
  char buffer[200];
  const char *bufptr = buffer;
  const char **bufp = &bufptr;
  int at_h_index = at_h_pos - *strp;
  const char *errmsg;

  memcpy (buffer, *strp, at_h_index);
  strcpy (buffer + at_h_index, *strp + at_h_index + 2);

  errmsg = cgen_parse_address (cd, bufp, opindex, opinfo, resultp, valuep);

  /* bump up real string pointer appropriately and account for the @h as well */
  *strp += (bufptr - buffer) + 2;

  return errmsg;
} 


static const char *
parse_i5 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  enum cgen_parse_operand_result result_type ATTRIBUTE_UNUSED;
  bfd_vma value;

  if (strncasecmp (*strp, "%lo(", 4) == 0)
    {
      *strp += 4;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_LO5,
					&result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_LO16_LO5,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      value &= 0x1f;
      *valuep = value;
      return errmsg;
    }
  else if (strncasecmp (*strp, "%xlo(", 5) == 0)
    {
      *strp += 5;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_XLO5,
				        &result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_HI16_LO5,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      value = ((value >> 16) & 0x1f);
      *valuep = value;
      return errmsg;
    }

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) &value);
  if (value > 0x1f)
    return _("immediate value out of range");
  *valuep = value;
  return errmsg;
}

/* for STS8s */

static const char *
parse_i10 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  enum cgen_parse_operand_result result_type ATTRIBUTE_UNUSED;
  bfd_vma value;

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) &value);
  if (value > 0x3ff)
    return _("immediate value out of range");
  *valuep = value;
  return errmsg;
}

/* for STS16s */

static const char *
parse_i9 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  enum cgen_parse_operand_result result_type ATTRIBUTE_UNUSED;
  bfd_vma value;

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) &value);
  if (value > 0x1ff)
    return _("immediate value out of range");
  *valuep = value;
  return errmsg;
}

/* check dual mode instruction...could be register or immediate value */
static const char *
parse_Rbi5 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg = NULL;
  enum cgen_parse_operand_result result_type ATTRIBUTE_UNUSED;
  bfd_vma value;
  bfd_vma extra = 0;

  nios_Rbi5 = NIOS_RBI5_IMMEDIATE;

  if (strncasecmp (*strp, "%lo(", 4) == 0)
    {
      *strp += 4;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_LO5,
					&result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_LO16_LO5,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      value &= 0x1f;
      *valuep = value;
      return errmsg;
    }
  else if (strncasecmp (*strp, "%xlo(", 5) == 0)
    {
      *strp += 5;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_XLO5,
					   &result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_HI16_LO5,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      value = ((value >> 16) & 0x1f);
      *valuep = value;
      return errmsg;
    }
  else if (strncmp (*strp, "%r", 2) == 0 ||
	   strncmp (*strp, "%g", 2) == 0)
    {
      *strp += 2;
      nios_Rbi5 = NIOS_RBI5_REGISTER;
    }
  else if (strncmp (*strp, "%i", 2) == 0)
    {
      *strp += 2;
      extra = 24;
      nios_Rbi5 = NIOS_RBI5_REGISTER;
    }
  else if (strncmp (*strp, "%o", 2) == 0)
    {
      *strp += 2;
      extra = 8;
      nios_Rbi5 = NIOS_RBI5_REGISTER;
    }
  else if (strncmp (*strp, "%l", 2) == 0)
    {
      *strp += 2;
      extra = 16;
      nios_Rbi5 = NIOS_RBI5_REGISTER;
    }
  else if (strncmp (*strp, "%sp", 3) == 0)
    {
      *strp += 2;
      *valuep = 14;
      nios_Rbi5 = NIOS_RBI5_REGISTER;
      return errmsg;
    }

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) valuep);
  *valuep += extra;

  if (*valuep > 0x1f)
    return _("immediate value out of range");
  return errmsg;
}

/* Handle %hi(), %xhi().  */

static const char *
parse_i11 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  enum cgen_parse_operand_result result_type = CGEN_PARSE_OPERAND_RESULT_NUMBER;
  bfd_vma value;

  nios_parsed_i11 = 1;

  if (strncasecmp (*strp, "%hi(", 4) == 0)
    {
      *strp += 4;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_HI11,
					   &result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_LO16_HI11,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      if (result_type == CGEN_PARSE_OPERAND_RESULT_NUMBER)
	value = (value & 0xffff) >> 5;
      *valuep = value;
      return errmsg;
    }
  else if (strncasecmp (*strp, "%xhi(", 5) == 0)
    {
      *strp += 5;
      if (**strp == '-' || ISDIGIT(**strp))
	{
	  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}
      else 
        {
	  char *k = strchr (*strp, '@');
	  if (k != NULL && k[1] == 'h')
	    {
	      errmsg = parse_h_address (cd, strp, k, opindex, BFD_RELOC_NIOS_H_XHI11,
					   &result_type, &value);
	      value >>= 1;
	    }
	  else
	    {
	      errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NIOS_HI16_HI11,
					   &result_type, &value);
	    }
	  if (**strp != ')')
	    return _("missing ')'");
	  ++*strp;
	}

      if (result_type == CGEN_PARSE_OPERAND_RESULT_NUMBER)
	value = (value >> 21);
      *valuep = value;
      return errmsg;
    }

  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
  if ((long)value > 0x7ff || (long)value < -0x800)
    return _("immediate value out of range");
  value &= 0x7ff;
  *valuep = value;
  return errmsg;
}

static const char *
parse_save_i8v (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  bfd_vma value;

  errmsg = cgen_parse_signed_integer (cd, strp, opindex, (long *) &value);
  if ((long)value > 0)
    return _("stack alteration value must be negative or zero");
  value = 0-(long)value;
    
  if (value > 0xff)
    return _("immediate value out of range");
  *valuep = value;
  return errmsg;
}

/* parse possible condition code masks */
static const char *
parse_i4w (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  bfd_vma value;
  char ch, ch2;
  int not_flag = 0;
  int cc = 0;

  value = 0xffff;

  if (strncasecmp (*strp, "cc_", 3) == 0)
    {
      cc = 1;
      *strp += 3;
    }
  else if (strncasecmp (*strp, "!cc_", 4) == 0)
    {
      cc = 1;
      *strp += 4;
      not_flag = 1;
    }

  if (cc)
    {
      errmsg = NULL;
      ch = **strp;
      ++*strp;
      switch (ch)
	{
	case 'z':
	  value = CC_Z;
	  break;
	
	case 'g':
	  ch2 = **strp;
	  if (ch2 == 'e')
	    {
	      value = CC_GE;
	      ++*strp;
	    }
	  else if (ch2 == 't')
	    {
	      value = CC_GT;
	      ++*strp;
	    }
	  break;
	
	case 'l':
	  ch2 = **strp;
	  if (ch2 == 'e')
	    {
	      value = CC_LE;
	      ++*strp;
	    }
	  else if (ch2 == 't')
	    {
	      value = CC_LT;
	      ++*strp;
	    }
	  else if (ch2 == 's')
	    {
	      value = CC_LS;
	      ++*strp;
	    }
	  break;
	
	case 'h':
	  if (**strp == 'i')
	    {
	      value = CC_HI;
	      ++*strp;
	    }
	  break;
	
	case 'p':
	  ch2 = **strp;
	  if (ch2 == 'l')
	    {
	      value = CC_PL;
	      ++*strp;
	    }
	  else if (ch2 == '\0' || ISSPACE(ch2))
	    value = CC_PL;
	  break;

	case 'm':
	  ch2 = **strp;
	  if (ch2 == 'i')
	    {
	      value = CC_MI;
	      ++*strp;
	    }
	  break;

	case 'e':
	  ch2 = **strp;
	  if (ch2 == 'q')
	    {
	      value = CC_Z;
	      ++*strp;
	    }
	  break;
	
	case 'n':
	  ch2 = **strp;
	  if (ch2 == 'z' || ch2 == 'e')
	    {
	      value = CC_NZ;
	      ++*strp;
	    }
	  else if (ch2 == 'e')
	    {
	      value = CC_NZ;
	      ++*strp;
	    }
	  else if (ch2 == 'c')
	    {
	      value = CC_NC;
	      ++*strp;
	    }
	  else if (ch2 == 'v')
	    {
	      value = CC_NV;
	      ++*strp;
	    }
	  else if (ch2 == '\0' || ISSPACE(ch2))
	    {
	      value = CC_MI;
	    }
	  break;
	
	case 'v':
	  ch2 = **strp;
	  if (ch2 == 'c')
	    {
	      value = CC_NV;
	      ++*strp;
	    }
	  else if (ch2 == 's')
	    {
	      value = CC_V;
	      ++*strp;
	    }
	  else if (ch2 == '\0' || ISSPACE(ch2))
	    {
	      value = CC_V;
	    }
	  break;
	
	case 'c':
	  ch2 = **strp;
	  if (ch2 == 'c')
	    {
	      value = CC_NC;
	      ++*strp;
	    }
	  else if (ch2 == 's')
	    {
	      value = CC_C;
	      ++*strp;
	    }
	  else if (ch2 == '\0' || ISSPACE(ch2))
	    {
	      value = CC_C;
	    }
	  break;
	}
	
	if ((value == 0xffff || **strp != '\0') && !ISSPACE (**strp))
	  return _("invalid condition code mask specified");
	if (not_flag)
	  value ^= 1;
    }
  else
    {
      errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) &value);
      if (value > CC_MAX)
	return _("invalid condition code mask specified");
    }
  *valuep = value;
  return errmsg;
}

/* parse possible condition code masks for ifs */
static const char *
parse_i4wn (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;

  errmsg = parse_i4w (cd, strp, opindex, valuep);
  *valuep ^= 1;
  return errmsg;
}



ATTRIBUTE_UNUSED static const char *
parse_i16 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;
  bfd_vma value;

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) &value);
  if (value > 0xffff)
    return _("immediate value out of range");
  *valuep = value;
  return errmsg;
}

ATTRIBUTE_UNUSED static const char *
parse_i32 (CGEN_CPU_DESC cd,
		    const char ** strp,
		    int opindex,
		    unsigned long * valuep)
{
  const char *errmsg;

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, (unsigned long *) valuep);
  return errmsg;
}


/* -- dis.c */

/* Main entry point for operand parsing.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `parse_insn_normal', but keeping it
   separate makes clear the interface between `parse_insn_normal' and each of
   the handlers.
*/

const char *
nios_cgen_parse_operand (CGEN_CPU_DESC cd,
		    int opindex,
		    const char ** strp,
		    CGEN_FIELDS * fields)
{
  const char * errmsg = NULL;
  /* Used by scalar operands that still need to be parsed.  */
  long junk ATTRIBUTE_UNUSED;

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_CTLC, (unsigned long *) &fields->f_CTLc);
      break;
    case NIOS_OPERAND_RBI5 :
      errmsg = parse_Rbi5 (cd, strp, NIOS_OPERAND_RBI5, (unsigned long *) &fields->f_Rbi5);
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_BSRR_REL6, 0, NULL, &value);
        fields->f_bsrr_i6_rel = value;
      }
      break;
    case NIOS_OPERAND_I1 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_I1, (unsigned long *) &fields->f_i1);
      break;
    case NIOS_OPERAND_I10 :
      errmsg = parse_i10 (cd, strp, NIOS_OPERAND_I10, (unsigned long *) &fields->f_i10);
      break;
    case NIOS_OPERAND_I11 :
      errmsg = parse_i11 (cd, strp, NIOS_OPERAND_I11, (unsigned long *) &fields->f_i11);
      break;
    case NIOS_OPERAND_I2 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_I2, (unsigned long *) &fields->f_i2);
      break;
    case NIOS_OPERAND_I4W :
      errmsg = parse_i4w (cd, strp, NIOS_OPERAND_I4W, (unsigned long *) &fields->f_i4w);
      break;
    case NIOS_OPERAND_I4WN :
      errmsg = parse_i4wn (cd, strp, NIOS_OPERAND_I4WN, (unsigned long *) &fields->f_i4w);
      break;
    case NIOS_OPERAND_I5 :
      errmsg = parse_i5 (cd, strp, NIOS_OPERAND_I5, (unsigned long *) &fields->f_i5);
      break;
    case NIOS_OPERAND_I6V :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_I6V, (unsigned long *) &fields->f_i6v);
      break;
    case NIOS_OPERAND_I8 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_I8, (unsigned long *) &fields->f_i8);
      break;
    case NIOS_OPERAND_I8V :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_I8V, (unsigned long *) &fields->f_i8v);
      break;
    case NIOS_OPERAND_I9 :
      errmsg = parse_i9 (cd, strp, NIOS_OPERAND_I9, (unsigned long *) &fields->f_i9);
      break;
    case NIOS_OPERAND_M16_R0 :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_h_m16_gr0, & junk);
      break;
    case NIOS_OPERAND_M16_RA :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Ra);
      break;
    case NIOS_OPERAND_M16_RB :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Rb);
      break;
    case NIOS_OPERAND_M16_RP :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_bp_names, & fields->f_Rp);
      break;
    case NIOS_OPERAND_M16_RZ :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Rz);
      break;
    case NIOS_OPERAND_M16_I6 :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_M16_I6, 0, NULL,  & value);
        fields->f_i6_rel_h = value;
      }
      break;
    case NIOS_OPERAND_M16_I8V :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_M16_I8V, 0, NULL,  & value);
        fields->f_i8v_rel_h = value;
      }
      break;
    case NIOS_OPERAND_M16_SP :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_h_m16_sp, & junk);
      break;
    case NIOS_OPERAND_M32_R0 :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr0_name, & junk);
      break;
    case NIOS_OPERAND_M32_RA :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Ra);
      break;
    case NIOS_OPERAND_M32_RB :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Rb);
      break;
    case NIOS_OPERAND_M32_RP :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_bp_names, & fields->f_Rp);
      break;
    case NIOS_OPERAND_M32_RZ :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_gr_names, & fields->f_Rz);
      break;
    case NIOS_OPERAND_M32_I6 :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_M32_I6, 0, NULL,  & value);
        fields->f_i6_rel_w = value;
      }
      break;
    case NIOS_OPERAND_M32_I8V :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_M32_I8V, 0, NULL,  & value);
        fields->f_i8v_rel_w = value;
      }
      break;
    case NIOS_OPERAND_M32_SP :
      errmsg = cgen_parse_keyword (cd, strp, & nios_cgen_opval_h_m32_sp, & junk);
      break;
    case NIOS_OPERAND_O1 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_O1, (unsigned long *) &fields->f_o1);
      break;
    case NIOS_OPERAND_O2 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_O2, (unsigned long *) &fields->f_o2);
      break;
    case NIOS_OPERAND_REL11 :
      {
        bfd_vma value;
        errmsg = cgen_parse_address (cd, strp, NIOS_OPERAND_REL11, 0, NULL,  & value);
        fields->f_i11_rel = value;
      }
      break;
    case NIOS_OPERAND_SAVE_I8V :
      errmsg = parse_save_i8v (cd, strp, NIOS_OPERAND_SAVE_I8V, (unsigned long *) &fields->f_i8v);
      break;
    case NIOS_OPERAND_SI11 :
      errmsg = cgen_parse_signed_integer (cd, strp, NIOS_OPERAND_SI11, (long *) &fields->f_i11);
      break;
    case NIOS_OPERAND_SI5 :
      errmsg = cgen_parse_signed_integer (cd, strp, NIOS_OPERAND_SI5, (long *) &fields->f_i5);
      break;
    case NIOS_OPERAND_X1 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_X1, (unsigned long *) &fields->f_x1);
      break;
    case NIOS_OPERAND_XRA :
      errmsg = cgen_parse_unsigned_integer (cd, strp, NIOS_OPERAND_XRA, (unsigned long *) &fields->f_Ra);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while parsing.\n"), opindex);
      abort ();
  }

  return errmsg;
}

cgen_parse_fn * const nios_cgen_parse_handlers[] = 
{
  parse_insn_normal,
};

void
nios_cgen_init_asm (cd)
     CGEN_CPU_DESC cd;
{
  nios_cgen_init_opcode_table (cd);
  nios_cgen_init_ibld_table (cd);
  cd->parse_handlers = & nios_cgen_parse_handlers[0];
  cd->parse_operand = nios_cgen_parse_operand;
}


/* Default insn parser.

   The syntax string is scanned and operands are parsed and stored in FIELDS.
   Relocs are queued as we go via other callbacks.

   ??? Note that this is currently an all-or-nothing parser.  If we fail to
   parse the instruction, we return 0 and the caller will start over from
   the beginning.  Backtracking will be necessary in parsing subexpressions,
   but that can be handled there.  Not handling backtracking here may get
   expensive in the case of the m68k.  Deal with later.

   Returns NULL for success, an error message for failure.  */

static const char *
parse_insn_normal (CGEN_CPU_DESC cd,
		   const CGEN_INSN *insn,
		   const char **strp,
		   CGEN_FIELDS *fields)
{
  /* ??? Runtime added insns not handled yet.  */
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  const char *str = *strp;
  const char *errmsg;
  const char *p;
  const CGEN_SYNTAX_CHAR_TYPE * syn;
#ifdef CGEN_MNEMONIC_OPERANDS
  /* FIXME: wip */
  int past_opcode_p;
#endif

  /* For now we assume the mnemonic is first (there are no leading operands).
     We can parse it without needing to set up operand parsing.
     GAS's input scrubber will ensure mnemonics are lowercase, but we may
     not be called from GAS.  */
  p = CGEN_INSN_MNEMONIC (insn);
  while (*p && TOLOWER (*p) == TOLOWER (*str))
    ++p, ++str;

  if (* p)
    return _("unrecognized instruction");

#ifndef CGEN_MNEMONIC_OPERANDS
  if (* str && ! ISSPACE (* str))
    return _("unrecognized instruction");
#endif

  CGEN_INIT_PARSE (cd);
  cgen_init_parse_operand (cd);
#ifdef CGEN_MNEMONIC_OPERANDS
  past_opcode_p = 0;
#endif

  /* We don't check for (*str != '\0') here because we want to parse
     any trailing fake arguments in the syntax string.  */
  syn = CGEN_SYNTAX_STRING (syntax);

  /* Mnemonics come first for now, ensure valid string.  */
  if (! CGEN_SYNTAX_MNEMONIC_P (* syn))
    abort ();

  ++syn;

  while (* syn != 0)
    {
      /* Non operand chars must match exactly.  */
      if (CGEN_SYNTAX_CHAR_P (* syn))
	{
	  /* FIXME: While we allow for non-GAS callers above, we assume the
	     first char after the mnemonic part is a space.  */
	  /* FIXME: We also take inappropriate advantage of the fact that
	     GAS's input scrubber will remove extraneous blanks.  */
	  if (TOLOWER (*str) == TOLOWER (CGEN_SYNTAX_CHAR (* syn)))
	    {
#ifdef CGEN_MNEMONIC_OPERANDS
	      if (CGEN_SYNTAX_CHAR(* syn) == ' ')
		past_opcode_p = 1;
#endif
	      ++ syn;
	      ++ str;
	    }
	  else if (*str)
	    {
	      /* Syntax char didn't match.  Can't be this insn.  */
	      static char msg [80];

	      /* xgettext:c-format */
	      sprintf (msg, _("syntax error (expected char `%c', found `%c')"),
		       CGEN_SYNTAX_CHAR(*syn), *str);
	      return msg;
	    }
	  else
	    {
	      /* Ran out of input.  */
	      static char msg [80];

	      /* xgettext:c-format */
	      sprintf (msg, _("syntax error (expected char `%c', found end of instruction)"),
		       CGEN_SYNTAX_CHAR(*syn));
	      return msg;
	    }
	  continue;
	}

#ifdef CGEN_MNEMONIC_OPERANDS
      (void) past_opcode_p;
#endif
      /* We have an operand of some sort.  */
      errmsg = cd->parse_operand (cd, CGEN_SYNTAX_FIELD (*syn), &str, fields);
      if (errmsg)
	return errmsg;

      /* Done with this operand, continue with next one.  */
      ++ syn;
    }

  /* If we're at the end of the syntax string, we're done.  */
  if (* syn == 0)
    {
      /* FIXME: For the moment we assume a valid `str' can only contain
	 blanks now.  IE: We needn't try again with a longer version of
	 the insn and it is assumed that longer versions of insns appear
	 before shorter ones (eg: lsr r2,r3,1 vs lsr r2,r3).  */
      while (ISSPACE (* str))
	++ str;

      if (* str != '\0')
	return _("junk at end of line"); /* FIXME: would like to include `str' */

      return NULL;
    }

  /* We couldn't parse it.  */
  return _("unrecognized instruction");
}

/* Main entry point.
   This routine is called for each instruction to be assembled.
   STR points to the insn to be assembled.
   We assume all necessary tables have been initialized.
   The assembled instruction, less any fixups, is stored in BUF.
   Remember that if CGEN_INT_INSN_P then BUF is an int and thus the value
   still needs to be converted to target byte order, otherwise BUF is an array
   of bytes in target byte order.
   The result is a pointer to the insn's entry in the opcode table,
   or NULL if an error occured (an error message will have already been
   printed).

   Note that when processing (non-alias) macro-insns,
   this function recurses.

   ??? It's possible to make this cpu-independent.
   One would have to deal with a few minor things.
   At this point in time doing so would be more of a curiosity than useful
   [for example this file isn't _that_ big], but keeping the possibility in
   mind helps keep the design clean.  */

const CGEN_INSN *
nios_cgen_assemble_insn (CGEN_CPU_DESC cd,
			   const char *str,
			   CGEN_FIELDS *fields,
			   CGEN_INSN_BYTES_PTR buf,
			   char **errmsg)
{
  const char *start;
  CGEN_INSN_LIST *ilist;
  const char *parse_errmsg = NULL;
  const char *insert_errmsg = NULL;
  int recognized_mnemonic = 0;

  /* Skip leading white space.  */
  while (ISSPACE (* str))
    ++ str;

  /* The instructions are stored in hashed lists.
     Get the first in the list.  */
  ilist = CGEN_ASM_LOOKUP_INSN (cd, str);

  /* Keep looking until we find a match.  */
  start = str;
  for ( ; ilist != NULL ; ilist = CGEN_ASM_NEXT_INSN (ilist))
    {
      const CGEN_INSN *insn = ilist->insn;
      recognized_mnemonic = 1;

#ifdef CGEN_VALIDATE_INSN_SUPPORTED
      /* Not usually needed as unsupported opcodes
	 shouldn't be in the hash lists.  */
      /* Is this insn supported by the selected cpu?  */
      if (! nios_cgen_insn_supported (cd, insn))
	continue;
#endif
      /* If the RELAXED attribute is set, this is an insn that shouldn't be
	 chosen immediately.  Instead, it is used during assembler/linker
	 relaxation if possible.  */
      if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_RELAXED) != 0)
	continue;

      str = start;

#if 0
      /* Skip this insn if str doesn't look right lexically.  */
      if (CGEN_INSN_RX (insn) != NULL &&
	  regexec ((regex_t *) CGEN_INSN_RX (insn), str, 0, NULL, 0) == REG_NOMATCH)
	continue;
#endif

      /* Allow parse/insert handlers to obtain length of insn.  */
      CGEN_FIELDS_BITSIZE (fields) = CGEN_INSN_BITSIZE (insn);

      parse_errmsg = CGEN_PARSE_FN (cd, insn) (cd, insn, & str, fields);
      if (parse_errmsg != NULL)
	continue;

      /* ??? 0 is passed for `pc'.  */
      insert_errmsg = CGEN_INSERT_FN (cd, insn) (cd, insn, fields, buf,
						 (bfd_vma) 0);
      if (insert_errmsg != NULL)
        continue;

      /* It is up to the caller to actually output the insn and any
         queued relocs.  */
      return insn;
    }

  {
    static char errbuf[150];
    const char *tmp_errmsg;
#ifdef CGEN_VERBOSE_ASSEMBLER_ERRORS
#define be_verbose 1
#else
#define be_verbose 0
#endif

    if (be_verbose)
      {
	/* If requesting verbose error messages, use insert_errmsg.
	   Failing that, use parse_errmsg.  */
	tmp_errmsg = (insert_errmsg ? insert_errmsg :
		      parse_errmsg ? parse_errmsg :
		      recognized_mnemonic ?
		      _("unrecognized form of instruction") :
		      _("unrecognized instruction"));

	if (strlen (start) > 50)
	  /* xgettext:c-format */
	  sprintf (errbuf, "%s `%.50s...'", tmp_errmsg, start);
	else
	  /* xgettext:c-format */
	  sprintf (errbuf, "%s `%.50s'", tmp_errmsg, start);
      }
    else
      {
	if (strlen (start) > 50)
	  /* xgettext:c-format */
	  sprintf (errbuf, _("bad instruction `%.50s...'"), start);
	else
	  /* xgettext:c-format */
	  sprintf (errbuf, _("bad instruction `%.50s'"), start);
      }

    *errmsg = errbuf;
    return NULL;
  }
}

#if 0 /* This calls back to GAS which we can't do without care.  */

/* Record each member of OPVALS in the assembler's symbol table.
   This lets GAS parse registers for us.
   ??? Interesting idea but not currently used.  */

/* Record each member of OPVALS in the assembler's symbol table.
   FIXME: Not currently used.  */

void
nios_cgen_asm_hash_keywords (cd, opvals)
     CGEN_CPU_DESC cd;
     CGEN_KEYWORD *opvals;
{
  CGEN_KEYWORD_SEARCH search = cgen_keyword_search_init (opvals, NULL);
  const CGEN_KEYWORD_ENTRY * ke;

  while ((ke = cgen_keyword_search_next (& search)) != NULL)
    {
#if 0 /* Unnecessary, should be done in the search routine.  */
      if (! nios_cgen_opval_supported (ke))
	continue;
#endif
      cgen_asm_record_register (cd, ke->name, ke->value);
    }
}

#endif /* 0 */
