/* Assembler interface for targets using CGEN. -*- C -*-
   CGEN: Cpu tools GENerator

   THIS FILE IS MACHINE GENERATED WITH CGEN.
   - the resultant file is machine generated, cgen-asm.in isn't

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2005, 2007, 2008, 2010
   Free Software Foundation, Inc.

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
#include <stdio.h>
#include "ansidecl.h"
#include "bfd.h"
#include "symcat.h"
#include "vc4-desc.h"
#include "vc4-opc.h"
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

#include <errno.h>

union floatbits {
  float f;
  uint32_t u;
};

static const char *
parse_floatimm6 (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
		 const char **strp,
		 int opindex ATTRIBUTE_UNUSED,
		 unsigned long *valuep)
{
  const char *startptr;
  char *endptr;
  union floatbits val;
  unsigned int exponent, signbit, mantissa;

  if (**strp == '#')
    (*strp)++;

  startptr = *strp;

  errno = 0;
  val.f = (float) strtod (startptr, &endptr);

  if (errno != 0)
    goto err_out;

  signbit = (val.u & 0x80000000) ? 1 : 0;
  exponent = (val.u >> 23) & 0xff;
  mantissa = val.u & 0x7fffff;

  /* r2: a zero exponent field encodes +-0.0 */
  if (val.f == 0)
    {
      *valuep = signbit << 5;
      *strp = endptr;
      return NULL;
    }

  if (exponent >= 124 && exponent < 132
      && (mantissa & 0x1fffff) == 0)
    {
      exponent -= 124;
      *valuep = (signbit << 5) | (exponent << 2) | (mantissa >> 21);
      *strp = endptr;
      return NULL;
    }

err_out:
  return "Bad floating-point immediate";
}

static const char *
parse_shifted_uimm (CGEN_CPU_DESC cd, const char **strp, int opindex,
		    unsigned long *valuep, unsigned bits, unsigned shift)
{
  const char *errmsg;
  unsigned mask = (1 << shift) - 1;
  unsigned long hi = 1 << bits;
  enum cgen_parse_operand_result result_type;
  unsigned long value;
  bfd_vma result;

  if (**strp == '#')
    (*strp)++;

  /* Ambiguity resolution: (rN++) looks like adding an expression "+", which
     fails to parse as an address.  */
  if (**strp == '+')
    return "post-inc";

  errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NONE, &result_type,
                               &result);

  if (errmsg)
    return errmsg;

  if (result_type != CGEN_PARSE_OPERAND_RESULT_NUMBER)
    return "use wider reloc";

  value = result;

  if (!errmsg && ((value & mask) != 0 || (value >> shift) >= hi))
    errmsg = "out-of-range immediate";
  else
    *valuep = value;

  return errmsg;
}

static const char *
parse_uimm6 (CGEN_CPU_DESC cd, const char **strp, int opindex,
	     unsigned long *valuep)
{
  return parse_shifted_uimm (cd, strp, opindex, valuep, 6, 0);
}

static const char *
parse_uimm5 (CGEN_CPU_DESC cd, const char **strp, int opindex,
	     unsigned long *valuep)
{
  return parse_shifted_uimm (cd, strp, opindex, valuep, 5, 0);
}

static const char *
parse_uimm4_shl2 (CGEN_CPU_DESC cd, const char **strp, int opindex,
		  unsigned long *valuep)
{
  return parse_shifted_uimm (cd, strp, opindex, valuep, 4, 2);
}

static const char *
parse_uimm5_shl2 (CGEN_CPU_DESC cd, const char **strp, int opindex,
		  unsigned long *valuep)
{
  return parse_shifted_uimm (cd, strp, opindex, valuep, 5, 2);
}

static const char *
parse_uimm5_shl3 (CGEN_CPU_DESC cd, const char **strp, int opindex,
		  unsigned long *valuep)
{
  return parse_shifted_uimm (cd, strp, opindex, valuep, 5, 3);
}

static const char *
parse_shifted_imm (CGEN_CPU_DESC cd, const char **strp, int opindex,
		   long *valuep, unsigned bits, unsigned shift)
{
  const char *errmsg;
  unsigned mask = (1 << shift) - 1;
  long lo = -(1 << (bits - 1)), hi = 1 << (bits - 1);
  enum cgen_parse_operand_result result_type;
  long value;
  bfd_vma result;

  if (**strp == '#')
    (*strp)++;

  /* Ambiguity resolution: (rN++) looks like adding an expression "+", which
     fails to parse as an address.  */
  if (**strp == '+')
    return "post-inc";

  errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NONE, &result_type,
                               &result);

  if (errmsg)
    return errmsg;

  if (result_type != CGEN_PARSE_OPERAND_RESULT_NUMBER)
    return "use wider reloc";

  if (result & 0x80000000)
    result |= ~(bfd_vma) 0xffffffff;

  value = (bfd_signed_vma) result;

  if (!errmsg && ((value & mask) != 0 || (value >> shift) < lo
		  || (value >> shift) >= hi))
    errmsg = "out-of-range immediate";
  else
    *valuep = value;

  return errmsg;
}

#define SHIFTED_IMM_FN(B,S)						\
  static const char *							\
  parse_imm##B##_shl##S (CGEN_CPU_DESC cd, const char **strp,		\
			 int opindex, long *valuep)			\
  {									\
    return parse_shifted_imm (cd, strp, opindex, valuep, (B), (S));	\
  }

SHIFTED_IMM_FN (6, 8)
SHIFTED_IMM_FN (6, 7)
SHIFTED_IMM_FN (6, 6)
SHIFTED_IMM_FN (6, 5)
SHIFTED_IMM_FN (6, 4)
SHIFTED_IMM_FN (6, 3)
SHIFTED_IMM_FN (6, 2)
SHIFTED_IMM_FN (6, 1)

SHIFTED_IMM_FN (16, 4)
SHIFTED_IMM_FN (16, 3)
SHIFTED_IMM_FN (16, 2)
SHIFTED_IMM_FN (16, 1)

static const char *
parse_imm4 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 4, 0);
}

static const char *
parse_imm6 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 6, 0);
}

static const char *
parse_imm12 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 12, 0);
}

static const char *
parse_imm16 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 16, 0);
}

static const char *
parse_imm27 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 27, 0);
}

static const char *
parse_imm32 (CGEN_CPU_DESC cd, const char **strp, int opindex,
             unsigned long *valuep)
{
  const char *errmsg;
  enum cgen_parse_operand_result result_type;
  bfd_vma result;

  if (**strp == '#')
    (*strp)++;

  errmsg = cgen_parse_address (cd, strp, opindex, BFD_RELOC_NONE, &result_type,
                               &result);

  if (errmsg)
    return errmsg;

  *valuep = (unsigned long) result;

  return 0;
}

static const char *
parse_pcrel27 (CGEN_CPU_DESC cd, const char **strp, int opindex,
	       bfd_reloc_code_real_type code,
	       enum cgen_parse_operand_result *result_type, bfd_vma *valuep)
{
  bfd_vma result;
  const char *errmsg;

  /* Instructions like "st r5,(lr)" are ambiguous since "lr" can be interpreted
     as a bracketed symbolic name when we meant it to be parsed as a register
     indirection.  Special-case the former to fail.  */
  if (**strp == '(')
    {
      const char *s = *strp;

      if (s[0] == '-' && s[1] == '-')
        return "looks like predec";

      while (ISALNUM (*++s))
        ;

      if (s[0] == '+' && s[1] == '+')
        return "looks like postinc";

      if (*s == ')')
        return "looks like indirection";
    }

  errmsg = cgen_parse_address (cd, strp, opindex, code, result_type, &result);

  if (!errmsg)
    *valuep = result;

  return errmsg;
}

static const char *
parse_shlN (CGEN_CPU_DESC cd, const char **strp,
            int opindex,
            unsigned long *valuep ATTRIBUTE_UNUSED,
            unsigned long shift)
{
  const char *scan = *strp;
  bfd_boolean is_multiply = FALSE;
  const char *errmsg;
  unsigned long uval;

  while (ISSPACE (*scan))
    scan++;

  if (strncmp (scan, "shl", 3) == 0
      || strncmp (scan, "lsl", 3) == 0)
    scan += 3;
  else if (strncmp (scan, "<<", 2) == 0)
    scan += 2;
  else if (strncmp (scan, "*", 1) == 0)
    {
      scan++;
      is_multiply = TRUE;
    }
  else
    return "no left shift";

  while (ISSPACE (*scan))
    scan++;

  if (!is_multiply && *scan == '#')
    scan++;

  *strp = scan;
  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, &uval);

  if (errmsg)
    return errmsg;

  if ((is_multiply && uval == (1ul << shift))
      || (!is_multiply && uval == shift))
    return 0;

  return "wrong shift amount";
}

#define PARSE_SHLN(N)                                             \
  static const char *                                             \
  parse_shl##N (CGEN_CPU_DESC cd, const char **strp, int opindex, \
                unsigned long *valuep)                            \
  {                                                               \
    return parse_shlN (cd, strp, opindex, valuep, (N));           \
  }

PARSE_SHLN(1)
PARSE_SHLN(2)
PARSE_SHLN(3)
PARSE_SHLN(4)
PARSE_SHLN(5)
PARSE_SHLN(6)
PARSE_SHLN(7)
PARSE_SHLN(8)

static const char *
parse_unsigned_int_maybe_postinc (CGEN_CPU_DESC cd, const char **strp,
                                  int opindex, unsigned long *valuep,
                                  bfd_boolean *postinc_p)
{
  int nesting = 0;
  char *ptr = (char *) *strp;
  char *term = 0, saved_char;
  const char *errmsg;

  *postinc_p = FALSE;

  while (*ptr != 0)
    {
      if (*ptr == '(')
        nesting++;
      else if (*ptr == ')')
        {
          if (nesting > 0)
            nesting--;
          else
            break;
        }
      else if (ptr[0] == '+' && ptr[1] == '+')
        {
          /* We have a postinc, but cgen_parse_unsigned_integer will misparse
             it.  Insert a zero-terminator temporarily as a workaround.  */
          term = ptr;
          saved_char = *ptr;
          *ptr = 0;
          break;
        }
      else if (*ptr == ',')
        break;
      ptr++;
    }

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, valuep);
  if (term)
    *ptr = saved_char;
  if (errmsg)
    return errmsg;

  if ((*strp)[0] == '+' && (*strp)[1] == '+')
    {
      (*strp) += 2;
      *postinc_p = TRUE;
    }

  return 0;
}

static const char *
parse_signed_int_maybe_postmod (CGEN_CPU_DESC cd, const char **strp,
                                int opindex, long *valuep,
                                bfd_boolean *postmod_p)
{
  int nesting = 0;
  char *ptr = (char *) *strp;
  char *term = 0, saved_char;
  const char *errmsg;

  *postmod_p = FALSE;

  while (*ptr != 0)
    {
      if (*ptr == '(')
        nesting++;
      else if (*ptr == ')')
        {
          if (nesting > 0)
            nesting--;
          else
            break;
        }
      else if (ptr[0] == '+' && ptr[1] == '=')
        {
          /* We have a postmod, but cgen_parse_signed_integer will misparse
             it.  Insert a zero-terminator temporarily as a workaround.  */
          term = ptr;
          saved_char = *ptr;
          *ptr = 0;
          break;
        }
      ptr++;
    }

  errmsg = cgen_parse_signed_integer (cd, strp, opindex, valuep);
  if (term)
    *ptr = saved_char;
  if (errmsg)
    return errmsg;

  if ((*strp)[0] == '+' && (*strp)[1] == '=')
    {
      (*strp) += 2;
      *postmod_p = TRUE;
    }

  return 0;
}

static const char *
parse_vc4_reg (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
               const char **strp,
               int opindex ATTRIBUTE_UNUSED,
               unsigned int *regno_out,
               unsigned int maxreg)
{
  int scanned, chars_read = 0;
  unsigned regno;

  if (**strp != 'r')
    return "expecting register";

  (*strp)++;

  scanned = sscanf (*strp, "%u%n", &regno, &chars_read);
  if (scanned == 0)
    return "expecting register number";

  if (regno > maxreg)
    return "register out of range";

  (*strp) += chars_read;

  *regno_out = regno;

  return 0;
}

/* Vector insn parsing.

   This parses a vector operand and encodes bits as:

   19     16 15         10 9                   0
   [r r r r] [f f f f f f] [v v v v v v v v v v]
       |           |                 `-encoded coordinate.
       |            `-added scalar reg, column offset flag & post-inc.
        `-extra coordinate bits for A operand.
*/

static const char *
parse_vector_reg (CGEN_CPU_DESC cd, const char **strp, int opindex,
                  unsigned long *valuep, vc4_operand whichop,
                  bfd_boolean extended)
{
  const char *ptr = *strp;
  vc4_vec_dir vec_dir;
  unsigned long y, x;
  const char *errmsg;
  unsigned long valbits = 0;
  bfd_boolean do_inc = FALSE;
  bfd_boolean column_offset = FALSE;
  bfd_boolean inc_here;
  unsigned scalar_reg = 15;
  bfd_boolean areg_p = (whichop == OP_A) && extended;

  if ((ptr[0] == 'H' && ptr[1] == 'X')
      || (ptr[0] == 'H' && ptr[1] == '1' && ptr[2] == '6'))
    vec_dir = HX;
  else if ((ptr[0] == 'H' && ptr[1] == 'Y')
           || (ptr[0] == 'H' && ptr[1] == '3' && ptr[2] == '2'))
    vec_dir = HY;
  else if (ptr[0] == 'H'
           || (ptr[0] == 'H' && ptr[1] == '8'))
    vec_dir = H;
  else if ((ptr[0] == 'V' && ptr[1] == 'X')
           || (ptr[0] == 'V' && ptr[1] == '1' && ptr[2] == '6'))
    vec_dir = VX;
  else if ((ptr[0] == 'V' && ptr[1] == 'Y')
           || (ptr[0] == 'V' && ptr[1] == '3' && ptr[2] == '2'))
    vec_dir = VY;
  else if (ptr[0] == 'V'
           || (ptr[0] == 'V' && ptr[1] == '8'))
    vec_dir = V;
  else if (ptr[0] == '-')
    {
      /* This is a special case.  Just hard-wire the "dash" encoding and
         return.  */
      *valuep = 0x380;
      *strp = ptr + 1;

      return 0;
    }
  else
    return "expected H/HX/HY/V/VX/VY";

  /* H8/H16/H32 and V8/V16/V32 happen to each be one char longer than their
     H/HX/HY and V/VX/VY aliases.  */
  if (ISDIGIT (ptr[1]))
    ptr++;

  if (vec_dir == H || vec_dir == V)
    ptr++;
  else
    ptr += 2;

  if (*ptr != '(')
    return "expected '('";

  ptr++;

  *strp = ptr;
  errmsg = parse_unsigned_int_maybe_postinc (cd, strp, opindex, &y, &inc_here);
  if (errmsg)
    return errmsg;

  if (extended && (vec_dir == H || vec_dir == HX || vec_dir == HY))
    do_inc |= inc_here;
  else if (inc_here)
    return "can't increment vertical";

  if (**strp != ',')
    return "expected ,";
  (*strp)++;

  errmsg = parse_unsigned_int_maybe_postinc (cd, strp, opindex, &x, &inc_here);
  if (errmsg)
    return errmsg;

  if (extended && (vec_dir == V || vec_dir == VX || vec_dir == VY))
    do_inc |= inc_here;
  else if (inc_here)
    return "can't increment horizontal";

  ptr = *strp;
  if (*ptr != ')')
    return "expected ')'";

  ptr++;

  if (extended && ptr[0] == '+' && ptr[1] == 'r')
    {
      unsigned long regno;
      int scanned, chars_read = 0;
      ptr += 2;
      scanned = sscanf (ptr, "%lu%n", &regno, &chars_read);
      if (scanned == 0)
        return "expecting register number";
      if (regno > 14)
        return "register out of range";
      ptr += chars_read;
      scalar_reg = regno;
    }

  if (extended && *ptr == '*')
    {
      ptr++;
      column_offset = TRUE;
    }

  if (x > 63)
    return "X position out of range";

  if (y > 63)
    return "Y position out of range";

  switch (vec_dir)
    {
    case H:
      if (!areg_p && (x & 15) != 0)
        return "can't encode X position";
      valbits = y & 63;
      valbits |= (x >> 4) << 7;
      if (areg_p)
        valbits |= (x & 15) << 16;
      break;
    case HX:
      if ((!areg_p && (x & 31) != 0)
          || (areg_p && (x & 31) >= 16))
        return "can't encode X position";
      valbits = y & 63;
      valbits |= 0x200;
      valbits |= (x >> 5) << 7;
      if (areg_p)
        valbits |= (x & 15) << 16;
      break;
    case HY:
      if ((!areg_p && x != 0)
          || (areg_p && x >= 16))
        return "can't encode X position";
      valbits = y & 63;
      valbits |= 0x300;
      if (areg_p)
        valbits |= (x & 15) << 16;
      break;
    case V:
      if (!areg_p)
        {
          if ((y & 15) != 0)
            return "can't encode Y position";
          valbits = y & 0x30;
          valbits |= x & 15;
          valbits |= 0x40;
          valbits |= (x >> 4) << 7;
        }
      else
        {
          valbits = y & 63;
          valbits |= (x >> 4) << 7;
          valbits |= 0x40;
          valbits |= (x & 15) << 16;
        }
     break;
    case VX:
      if ((x & 31) >= 16)
        return "can't encode X position";
      if (!areg_p)
        {
          if ((y & 15) != 0)
            return "can't encode Y position";
          valbits = y & 0x30;
          valbits |= x & 15;
          valbits |= 0x240;
          valbits |= (x >> 5) << 7;
        }
      else
        {
          valbits = y & 63;
          valbits |= 0x240;
          valbits |= (x >> 5) << 7;
          valbits |= (x & 15) << 16;
        }
      break;
    case VY:
      if (x >= 16)
        return "can't encode X position";
      if (!areg_p)
        {
          if ((y & 15) != 0)
            return "can't encode Y position";
          valbits = y & 0x30;
          valbits |= x & 15;
          valbits |= 0x340;
        }
      else
        {
          valbits = y & 63;
          valbits |= 0x340;
          valbits |= (x & 15) << 16;
        }
      break;
    }

  if (extended)
    {
      if (column_offset)
        valbits |= 0x400;

      if (do_inc)
        valbits |= 0x800;

      valbits |= scalar_reg << 12;
    }

  *valuep = valbits;
  *strp = ptr;

  return 0;
}

static const char *
parse_vec80aludreg (CGEN_CPU_DESC cd, const char **strp, int opindex,
                    unsigned long *valuep)
{
  return parse_vector_reg (cd, strp, opindex, valuep, OP_D, TRUE);
}

static const char *
parse_vec80aluareg (CGEN_CPU_DESC cd, const char **strp, int opindex,
                    unsigned long *valuep)
{
  return parse_vector_reg (cd, strp, opindex, valuep, OP_A, TRUE);
}

static const char *
parse_vec80alubreg (CGEN_CPU_DESC cd, const char **strp, int opindex,
                    unsigned long *valuep)
{
  return parse_vector_reg (cd, strp, opindex, valuep, OP_B, TRUE);
}

static int
parse_scalar_reg_update (const char **strp, unsigned long *acc_sru, int opcode)
{
  int scanned, chars_read = 0;
  unsigned regno;

  if (**strp == ' ')
    (*strp)++;

  if (**strp != 'r')
    return 1;

  (*strp)++;

  scanned = sscanf (*strp, "%u%n", &regno, &chars_read);
  if (scanned == 0)
    return 1;

  if (regno > 7)
    return 1;

  *acc_sru = regno | (opcode << 3) | SRU_BIT;

  (*strp) += chars_read;

  return 0;
}

/* Parses modifiers and encodes as:

   13            7 6     4  3  2     0
   [i i i i i i i] [p p p] [F] [r r r]
          |           |     |     `-repeat count
          |           |      `-set flags
          |            `-lane predication
           `-SRU or ACC settings.
*/

static const char *
parse_vec80mods (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
                 const char **strp,
                 int opindex ATTRIBUTE_UNUSED,
                 unsigned long *valuep)
{
  unsigned long repeat = 0;
  unsigned long acc_sru = 0;
  unsigned long predication = 0;
  bfd_boolean setf = FALSE;
  bfd_boolean sru_p = FALSE;
  bfd_boolean acc_p = FALSE;

  while (**strp != 0)
    {
      if (**strp == ' ')
        (*strp)++;

      if (strncmp (*strp, "REP", 3) == 0)
        {
          if (repeat)
            return "multiple REP specifiers";

          (*strp) += 3;
          if (strncmp (*strp, "2", 1) == 0)
            repeat = 1, (*strp)++;
          else if (strncmp (*strp, "4", 1) == 0)
            repeat = 2, (*strp)++;
          else if (strncmp (*strp, "8", 1) == 0)
            repeat = 3, (*strp)++;
          else if (strncmp (*strp, "16", 2) == 0)
            repeat = 4, (*strp) += 2;
          else if (strncmp (*strp, "32", 2) == 0)
            repeat = 5, (*strp) += 2;
          else if (strncmp (*strp, "64", 2) == 0)
            repeat = 6, (*strp) += 2;
          else if (strncmp (*strp, " r0", 3) == 0)
            repeat = 7, (*strp) += 3;
          else
            return "bad repeat count";
        }
      else if (strncmp (*strp, "SETF", 4) == 0)
        {
          setf = TRUE;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "ALL", 3) == 0)
        {
          predication = 0;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "NONE", 4) == 0)
        {
          predication = 1;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "IFZ", 3) == 0)
        {
          predication = 2;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "IFNZ", 4) == 0)
        {
          predication = 3;
          (*strp) += 4;
        }
      /* This one must come before other "IFN*" predicate checks.  */
      else if (strncmp (*strp, "IFNN", 4) == 0)
        {
          predication = 5;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "IFNC", 4) == 0)
        {
          predication = 7;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "IFN", 3) == 0)
        {
          predication = 4;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "IFC", 3) == 0)
        {
          predication = 6;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "ENA", 3) == 0)
        {
          if (sru_p)
            return "can't have ENA with SRU";
          acc_sru |= ENA_BIT;
          acc_p = TRUE;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "HIGH", 4) == 0)
        {
          if (sru_p)
            return "can't have HIGH with SRU";
          acc_sru |= HIGH_BIT;
          acc_p = TRUE;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "SIGN", 4) == 0)
        {
          if (sru_p)
            return "can't have SIGN with SRU";
          acc_sru |= SIGN_BIT;
          acc_p = TRUE;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "CLRA", 4) == 0)
        {
          if (sru_p)
            return "can't have CLRA with SRU";
          acc_sru |= CLRA_BIT;
          acc_p = TRUE;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "WBA", 3) == 0)
        {
          if (sru_p)
            return "can't have WBA with SRU";
          acc_sru |= WBA_BIT;
          acc_p = TRUE;
          (*strp) += 3;
        }
      else if (strncmp (*strp, "SUB", 3) == 0)
        {
          if (sru_p)
            return "can't have SUB with SRU";
          acc_sru |= SUB_BIT;
          acc_p = TRUE;
          (*strp) += 3;
        }
      else if (**strp
               && (strncmp ((*strp) + 1, "ACC", 3) == 0
                   || strncmp ((*strp) + 1, "ADD", 3) == 0))
        {
          if (sru_p)
            return "can't have ACC with SRU";
          acc_sru |= ENA_BIT;
          if (strncmp ((*strp) + 1, "ACC", 3) == 0)
            acc_sru |= WBA_BIT;
          if (**strp == 'S')
            acc_sru |= SIGN_BIT;
          else if (**strp != 'U')
            return "not UACC/SACC";
          if ((*strp)[4] == 'H')
            {
              acc_sru |= HIGH_BIT;
              (*strp)++;
            }
          acc_p = TRUE;
          (*strp) += 4;
        }
      else if (**strp
               && (strncmp ((*strp) + 1, "DEC", 3) == 0
                   || strncmp ((*strp) + 1, "SUB", 3) == 0))
        {
          if (sru_p)
            return "can't have DEC with SRU";
          acc_sru |= ENA_BIT;
          if (strncmp ((*strp) + 1, "DEC", 3) == 0)
            acc_sru |= WBA_BIT;
          if (**strp == 'S')
            acc_sru |= SIGN_BIT;
          else if (**strp != 'U')
            return "not UDEC/SDEC";
          if ((*strp)[4] == 'H')
            {
              acc_sru |= HIGH_BIT;
              (*strp)++;
            }
          acc_p = TRUE;
          (*strp) += 4;
        }
      else if (strncmp (*strp, "SUMS", 4) == 0
               || strncmp (*strp, "SUMU", 4) == 0)
        {
          int opcode = (*strp)[3] == 'S' ? 1 : 0;
          if (acc_p)
            return "can't have SUMS/SUMU with ACC";

          (*strp) += 4;

          if (parse_scalar_reg_update (strp, &acc_sru, opcode))
            return "error parsing scalar update reg";

          sru_p = TRUE;
        }
      else if (strncmp (*strp, "IMIN", 4) == 0)
        {
          if (acc_p)
            return "can't have IMIN with ACC";
          (*strp) += 4;
          if (parse_scalar_reg_update (strp, &acc_sru, 3))
            return "error parsing scalar update reg";
          sru_p = TRUE;
        }
      else if (strncmp (*strp, "IMAX", 4) == 0)
        {
          if (acc_p)
            return "can't have IMAX with ACC";
          (*strp) += 4;
          if (parse_scalar_reg_update (strp, &acc_sru, 5))
            return "error parsing scalar update reg";
          sru_p = TRUE;
        }
      else if (strncmp (*strp, "MAX", 3) == 0)
        {
          if (acc_p)
            return "can't have MAX with ACC";
          (*strp) += 3;
          if (parse_scalar_reg_update (strp, &acc_sru, 7))
            return "error parsing scalar update reg";
          sru_p = TRUE;
        }
      else
        return "unexpected modifier";
    }

  if (acc_p && sru_p)
    return "scalar reg update and accumulator ops";

  *valuep = repeat | (setf << 3) | (predication << 4) | (acc_sru << 7);

  return 0;
}

static const char *
parse_vec80mods_mem (CGEN_CPU_DESC cd, const char **strp, int opindex,
                     unsigned long *valuep)
{
  const char *err = parse_vec80mods (cd, strp, opindex, valuep);
  if (err)
    return err;
  if ((*valuep & 0x7f) != *valuep)
    return "can't use SRU or ACC modifiers with memory op";
  return 0;
}

static const char *
parse_vec48mod_setf (CGEN_CPU_DESC cd, const char **strp, int opindex,
                     unsigned long *valuep)
{
  unsigned long allbits;
  const char *err = parse_vec80mods (cd, strp, opindex, &allbits);
  if (err)
    return err;

  if (allbits == 0x8)
    *valuep = 1;
  else if (allbits == 0)
    *valuep = 0;
  else
    return "only setf modifier here";

  return 0;
}

static const char *
parse_vec48imm_mods (CGEN_CPU_DESC cd, const char **strp, int opindex,
                     unsigned long *valuep)
{
  unsigned long allbits;
  const char *err = parse_vec80mods (cd, strp, opindex, &allbits);
  if (err)
    return err;

  if ((allbits & 0x78) != allbits)
    return "only setf/predication modifiers here";

  *valuep = (allbits >> 3) & 15;
  return 0;
}

/* Parses an address with offset & register-modify.

   25     22 21         16 15                              0
   [s s s s] [a a a a a a] [i i i i i i i i i i i i i i i i]
       |           |                       `-immediate offset
       |            `-ra (or rd for stores)
        `-rs
*/

static const char *
parse_ld_st_addr (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
                  const char **strp,
                  int opindex ATTRIBUTE_UNUSED,
                  unsigned long *valuep)
{
  unsigned rs, rad = 15;
  long offset = 0;
  bfd_boolean postmod = FALSE;
  const char *errmsg;

  errmsg = parse_vc4_reg (cd, strp, opindex, &rs, 15);
  if (errmsg)
    return errmsg;

  if ((*strp)[0] == '+' && (*strp)[1] != '=')
    {
      (*strp)++;
      errmsg = parse_signed_int_maybe_postmod (cd, strp, opindex, &offset,
                                               &postmod);
      if (errmsg)
        return errmsg;
    }
  else if ((*strp)[0] == '+' && (*strp)[1] == '=')
    {
      (*strp) += 2;
      postmod = TRUE;
    }

  if (postmod)
    {
      errmsg = parse_vc4_reg (cd, strp, opindex, &rad, 14);
      if (errmsg)
        return errmsg;
    }

  *valuep = (offset & 0xffff) | (rad << 18) | (rs << 22);

  return 0;
}

static const char *
parse_vec80ldaddr (CGEN_CPU_DESC cd, const char **strp, int opindex,
                   unsigned long *valuep)
{
  return parse_ld_st_addr (cd, strp, opindex, valuep);
}

static const char *
parse_vec80staddr (CGEN_CPU_DESC cd, const char **strp, int opindex,
                   unsigned long *valuep)
{
  return parse_ld_st_addr (cd, strp, opindex, valuep);
}

static const char *
parse_dummy (CGEN_CPU_DESC cd, const char **strp, int opindex,
             unsigned long *valuep)
{
  *valuep = 0;
  return 0;
}

static const char *
parse_plus_sreg (CGEN_CPU_DESC cd, const char **strp, int opindex,
                 unsigned long *valuep, unsigned whichreg)
{
  const char *errmsg;
  unsigned int regno;

  if (**strp != '+')
    {
      *valuep = 0;
      return 0;
    }

  (*strp)++;

  errmsg = parse_vc4_reg (cd, strp, opindex, &regno, 7);
  if (errmsg)
    return errmsg;

  if (regno != whichreg)
    return "unexpected register";

  *valuep = 1;
  return 0;
}

#define PLUS_SREG(X)                                                    \
  static const char *                                                   \
  parse_plus_sr##X (CGEN_CPU_DESC cd, const char **strp, int opindex,   \
                    unsigned long *valuep)                              \
  {                                                                     \
    return parse_plus_sreg (cd, strp, opindex, valuep, (X));            \
  }

PLUS_SREG(0)
PLUS_SREG(1)
PLUS_SREG(2)
PLUS_SREG(3)
PLUS_SREG(4)
PLUS_SREG(5)
PLUS_SREG(6)
PLUS_SREG(7)

static const char *
parse_vec48hvec (CGEN_CPU_DESC cd, const char **strp, int opindex,
                 unsigned long *valuep, vc4_operand whichop)
{
  const char *errmsg = parse_vector_reg (cd, strp, opindex, valuep, whichop,
                                         FALSE);

  if (errmsg)
    return errmsg;

  if ((*valuep & 0x3ff) != *valuep)
    return "too complicated for 48-bit insn";

  if ((*valuep & 0x40) != 0)
    return "not an H reg";

  return 0;
}

static const char *
parse_vec48vvec (CGEN_CPU_DESC cd, const char **strp, int opindex,
                 unsigned long *valuep, vc4_operand whichop)
{
  const char *errmsg = parse_vector_reg (cd, strp, opindex, valuep, whichop,
                                         FALSE);

  if (errmsg)
    return errmsg;

  if ((*valuep & 0x3ff) != *valuep)
    return "too complicated for 48-bit insn";

  if ((*valuep & 0x40) == 0)
    return "not a V reg";

  return 0;
}

static const char *
parse_vec48aludreg_h (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48hvec (cd, strp, opindex, valuep, OP_D);
}

static const char *
parse_vec48aludreg_v (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48vvec (cd, strp, opindex, valuep, OP_D);
}

static const char *
parse_vec48aluareg_h (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48hvec (cd, strp, opindex, valuep, OP_A);
}

static const char *
parse_vec48aluareg_v (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48vvec (cd, strp, opindex, valuep, OP_A);
}

static const char *
parse_vec48alubreg_h (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48hvec (cd, strp, opindex, valuep, OP_B);
}

static const char *
parse_vec48alubreg_v (CGEN_CPU_DESC cd, const char **strp, int opindex,
                      unsigned long *valuep)
{
  return parse_vec48vvec (cd, strp, opindex, valuep, OP_B);
}

static const char *
parse_vec48sclr (CGEN_CPU_DESC cd, const char **strp, int opindex,
                 unsigned long *valuep)
{
  unsigned reg;
  const char *errmsg = parse_vc4_reg (cd, strp, opindex, &reg, 15);
  if (errmsg)
    return errmsg;
  *valuep = reg;
  return 0;
}

/* -- dis.c */

const char * vc4_cgen_parse_operand
  (CGEN_CPU_DESC, int, const char **, CGEN_FIELDS *);

/* Main entry point for operand parsing.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `parse_insn_normal', but keeping it
   separate makes clear the interface between `parse_insn_normal' and each of
   the handlers.  */

const char *
vc4_cgen_parse_operand (CGEN_CPU_DESC cd,
			   int opindex,
			   const char ** strp,
			   CGEN_FIELDS * fields)
{
  const char * errmsg = NULL;
  /* Used by scalar operands that still need to be parsed.  */
  long junk ATTRIBUTE_UNUSED;

  switch (opindex)
    {
    case VC4_OPERAND_ADDCMPBAREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      errmsg = parse_imm4 (cd, strp, VC4_OPERAND_ADDCMPBIMM, (long *) (& fields->f_op7_4s));
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      errmsg = cgen_parse_signed_integer (cd, strp, VC4_OPERAND_ADDSPOFFSET, (long *) (& fields->f_addspoffset));
      break;
    case VC4_OPERAND_ALU16DREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op3_0);
      break;
    case VC4_OPERAND_ALU16IMM :
      errmsg = parse_uimm5 (cd, strp, VC4_OPERAND_ALU16IMM, (unsigned long *) (& fields->f_op8_4));
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      errmsg = parse_uimm5_shl3 (cd, strp, VC4_OPERAND_ALU16IMM_SHL3, (unsigned long *) (& fields->f_op8_4_shl3));
      break;
    case VC4_OPERAND_ALU16SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ALU32AREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op31_27);
      break;
    case VC4_OPERAND_ALU32BREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op20_16);
      break;
    case VC4_OPERAND_ALU32COND :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_dotcond, & fields->f_op26_23);
      break;
    case VC4_OPERAND_ALU32DREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU32MISSINGAREG :
      errmsg = parse_dummy (cd, strp, VC4_OPERAND_ALU32MISSINGAREG, (unsigned long *) (& fields->f_op31_27));
      break;
    case VC4_OPERAND_ALU48IDREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU48IMMU :
      errmsg = parse_imm32 (cd, strp, VC4_OPERAND_ALU48IMMU, (unsigned long *) (& fields->f_op47_16));
      break;
    case VC4_OPERAND_ALU48ISREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op9_5);
      break;
    case VC4_OPERAND_ALU48PCREL :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_ALU48PCREL, 0, NULL,  & value);
        fields->f_pcrel32_48 = value;
      }
      break;
    case VC4_OPERAND_APLUS_SR0 :
      errmsg = parse_plus_sr0 (cd, strp, VC4_OPERAND_APLUS_SR0, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR1 :
      errmsg = parse_plus_sr1 (cd, strp, VC4_OPERAND_APLUS_SR1, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR2 :
      errmsg = parse_plus_sr2 (cd, strp, VC4_OPERAND_APLUS_SR2, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR3 :
      errmsg = parse_plus_sr3 (cd, strp, VC4_OPERAND_APLUS_SR3, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR4 :
      errmsg = parse_plus_sr4 (cd, strp, VC4_OPERAND_APLUS_SR4, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR5 :
      errmsg = parse_plus_sr5 (cd, strp, VC4_OPERAND_APLUS_SR5, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR6 :
      errmsg = parse_plus_sr6 (cd, strp, VC4_OPERAND_APLUS_SR6, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_APLUS_SR7 :
      errmsg = parse_plus_sr7 (cd, strp, VC4_OPERAND_APLUS_SR7, (unsigned long *) (& fields->f_op18));
      break;
    case VC4_OPERAND_BCC32IMM :
      errmsg = parse_uimm6 (cd, strp, VC4_OPERAND_BCC32IMM, (unsigned long *) (& fields->f_op29_24));
      break;
    case VC4_OPERAND_BCC32SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op29_26);
      break;
    case VC4_OPERAND_BPLUS_SR0 :
      errmsg = parse_plus_sr0 (cd, strp, VC4_OPERAND_BPLUS_SR0, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR1 :
      errmsg = parse_plus_sr1 (cd, strp, VC4_OPERAND_BPLUS_SR1, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR2 :
      errmsg = parse_plus_sr2 (cd, strp, VC4_OPERAND_BPLUS_SR2, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR3 :
      errmsg = parse_plus_sr3 (cd, strp, VC4_OPERAND_BPLUS_SR3, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR4 :
      errmsg = parse_plus_sr4 (cd, strp, VC4_OPERAND_BPLUS_SR4, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR5 :
      errmsg = parse_plus_sr5 (cd, strp, VC4_OPERAND_BPLUS_SR5, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR6 :
      errmsg = parse_plus_sr6 (cd, strp, VC4_OPERAND_BPLUS_SR6, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_BPLUS_SR7 :
      errmsg = parse_plus_sr7 (cd, strp, VC4_OPERAND_BPLUS_SR7, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_CONDCODE :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_cond, & fields->f_op10_7);
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_cond, & fields->f_op11_8);
      break;
    case VC4_OPERAND_DISP5 :
      errmsg = parse_uimm5 (cd, strp, VC4_OPERAND_DISP5, (unsigned long *) (& fields->f_op20_16));
      break;
    case VC4_OPERAND_DPLUS_SR0 :
      errmsg = parse_plus_sr0 (cd, strp, VC4_OPERAND_DPLUS_SR0, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR1 :
      errmsg = parse_plus_sr1 (cd, strp, VC4_OPERAND_DPLUS_SR1, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR2 :
      errmsg = parse_plus_sr2 (cd, strp, VC4_OPERAND_DPLUS_SR2, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR3 :
      errmsg = parse_plus_sr3 (cd, strp, VC4_OPERAND_DPLUS_SR3, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR4 :
      errmsg = parse_plus_sr4 (cd, strp, VC4_OPERAND_DPLUS_SR4, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR5 :
      errmsg = parse_plus_sr5 (cd, strp, VC4_OPERAND_DPLUS_SR5, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR6 :
      errmsg = parse_plus_sr6 (cd, strp, VC4_OPERAND_DPLUS_SR6, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DPLUS_SR7 :
      errmsg = parse_plus_sr7 (cd, strp, VC4_OPERAND_DPLUS_SR7, (unsigned long *) (& fields->f_op43));
      break;
    case VC4_OPERAND_DUMMYABITS :
      errmsg = parse_dummy (cd, strp, VC4_OPERAND_DUMMYABITS, (unsigned long *) (& fields->f_dummyabits));
      break;
    case VC4_OPERAND_DUMMYDBITS :
      errmsg = parse_dummy (cd, strp, VC4_OPERAND_DUMMYDBITS, (unsigned long *) (& fields->f_op27_22));
      break;
    case VC4_OPERAND_FLOATIMM6 :
      errmsg = parse_floatimm6 (cd, strp, VC4_OPERAND_FLOATIMM6, (unsigned long *) (& fields->f_op21_16));
      break;
    case VC4_OPERAND_IMM6 :
      errmsg = parse_imm6 (cd, strp, VC4_OPERAND_IMM6, (long *) (& fields->f_op21_16s));
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      errmsg = parse_imm6_shl1 (cd, strp, VC4_OPERAND_IMM6_SHL1, (long *) (& fields->f_op21_16s_shl1));
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      errmsg = parse_imm6_shl2 (cd, strp, VC4_OPERAND_IMM6_SHL2, (long *) (& fields->f_op21_16s_shl2));
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      errmsg = parse_imm6_shl3 (cd, strp, VC4_OPERAND_IMM6_SHL3, (long *) (& fields->f_op21_16s_shl3));
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      errmsg = parse_imm6_shl4 (cd, strp, VC4_OPERAND_IMM6_SHL4, (long *) (& fields->f_op21_16s_shl4));
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      errmsg = parse_imm6_shl5 (cd, strp, VC4_OPERAND_IMM6_SHL5, (long *) (& fields->f_op21_16s_shl5));
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      errmsg = parse_imm6_shl6 (cd, strp, VC4_OPERAND_IMM6_SHL6, (long *) (& fields->f_op21_16s_shl6));
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      errmsg = parse_imm6_shl7 (cd, strp, VC4_OPERAND_IMM6_SHL7, (long *) (& fields->f_op21_16s_shl7));
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      errmsg = parse_imm6_shl8 (cd, strp, VC4_OPERAND_IMM6_SHL8, (long *) (& fields->f_op21_16s_shl8));
      break;
    case VC4_OPERAND_LDSTOFF :
      errmsg = parse_uimm4_shl2 (cd, strp, VC4_OPERAND_LDSTOFF, (unsigned long *) (& fields->f_ldstoff));
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      errmsg = parse_imm27 (cd, strp, VC4_OPERAND_MEM48OFFSET27, (long *) (& fields->f_offset27_48));
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      {
        bfd_vma value = 0;
        errmsg = parse_pcrel27 (cd, strp, VC4_OPERAND_MEM48PCREL27, 0, NULL,  & value);
        fields->f_pcrel27_48 = value;
      }
      break;
    case VC4_OPERAND_MEM48SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op47_43);
      break;
    case VC4_OPERAND_OFF16BASEREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_basereg, & fields->f_op9_8);
      break;
    case VC4_OPERAND_OFFSET12 :
      errmsg = parse_imm12 (cd, strp, VC4_OPERAND_OFFSET12, (long *) (& fields->f_offset12));
      break;
    case VC4_OPERAND_OFFSET16 :
      errmsg = parse_imm16 (cd, strp, VC4_OPERAND_OFFSET16, (long *) (& fields->f_op31_16s));
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      errmsg = parse_imm16_shl1 (cd, strp, VC4_OPERAND_OFFSET16_SHL1, (long *) (& fields->f_op31_16s_shl1));
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      errmsg = parse_imm16_shl2 (cd, strp, VC4_OPERAND_OFFSET16_SHL2, (long *) (& fields->f_op31_16s_shl2));
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      errmsg = parse_imm16_shl3 (cd, strp, VC4_OPERAND_OFFSET16_SHL3, (long *) (& fields->f_op31_16s_shl3));
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      errmsg = parse_imm16_shl4 (cd, strp, VC4_OPERAND_OFFSET16_SHL4, (long *) (& fields->f_op31_16s_shl4));
      break;
    case VC4_OPERAND_OFFSET23BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_OFFSET23BITS, 0, NULL,  & value);
        fields->f_offset23bits = value;
      }
      break;
    case VC4_OPERAND_OFFSET27BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_OFFSET27BITS, 0, NULL,  & value);
        fields->f_offset27bits = value;
      }
      break;
    case VC4_OPERAND_OPERAND10_0 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND10_0, (unsigned long *) (& fields->f_op10_0));
      break;
    case VC4_OPERAND_OPERAND47_16 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND47_16, (unsigned long *) (& fields->f_op47_16));
      break;
    case VC4_OPERAND_OPERAND79_48 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND79_48, (unsigned long *) (& fields->f_op79_48));
      break;
    case VC4_OPERAND_PCREL10BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL10BITS, 0, NULL,  & value);
        fields->f_pcrel10 = value;
      }
      break;
    case VC4_OPERAND_PCREL16 :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL16, 0, NULL,  & value);
        fields->f_pcrel16 = value;
      }
      break;
    case VC4_OPERAND_PCREL8BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL8BITS, 0, NULL,  & value);
        fields->f_pcrel8 = value;
      }
      break;
    case VC4_OPERAND_PCRELCC :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCRELCC, 0, NULL,  & value);
        fields->f_pcrelcc = value;
      }
      break;
    case VC4_OPERAND_PPENDREG0 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_0);
      break;
    case VC4_OPERAND_PPENDREG16 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_16);
      break;
    case VC4_OPERAND_PPENDREG24 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_24);
      break;
    case VC4_OPERAND_PPENDREG6 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_6);
      break;
    case VC4_OPERAND_PPSTARTREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_ppreg, & fields->f_op6_5);
      break;
    case VC4_OPERAND_PREGDST :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_preg, & fields->f_op4_0);
      break;
    case VC4_OPERAND_PREGSRC :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_preg, & fields->f_op20_16);
      break;
    case VC4_OPERAND_SETF_MOD :
      errmsg = parse_vec48mod_setf (cd, strp, VC4_OPERAND_SETF_MOD, (unsigned long *) (& fields->f_op38));
      break;
    case VC4_OPERAND_SHL1 :
      errmsg = parse_shl1 (cd, strp, VC4_OPERAND_SHL1, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL2 :
      errmsg = parse_shl2 (cd, strp, VC4_OPERAND_SHL2, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL3 :
      errmsg = parse_shl3 (cd, strp, VC4_OPERAND_SHL3, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL4 :
      errmsg = parse_shl4 (cd, strp, VC4_OPERAND_SHL4, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL5 :
      errmsg = parse_shl5 (cd, strp, VC4_OPERAND_SHL5, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL6 :
      errmsg = parse_shl6 (cd, strp, VC4_OPERAND_SHL6, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL7 :
      errmsg = parse_shl7 (cd, strp, VC4_OPERAND_SHL7, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SHL8 :
      errmsg = parse_shl8 (cd, strp, VC4_OPERAND_SHL8, (unsigned long *) (& junk));
      break;
    case VC4_OPERAND_SPOFFSET :
      errmsg = parse_uimm5_shl2 (cd, strp, VC4_OPERAND_SPOFFSET, (unsigned long *) (& fields->f_spoffset));
      break;
    case VC4_OPERAND_SWI_IMM :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_SWI_IMM, (unsigned long *) (& fields->f_op5_0));
      break;
    case VC4_OPERAND_V48AREG_H :
      errmsg = parse_vec48aluareg_h (cd, strp, VC4_OPERAND_V48AREG_H, (unsigned long *) (& fields->f_vec48areg));
      break;
    case VC4_OPERAND_V48AREG_V :
      errmsg = parse_vec48aluareg_v (cd, strp, VC4_OPERAND_V48AREG_V, (unsigned long *) (& fields->f_vec48areg));
      break;
    case VC4_OPERAND_V48BREG_H :
      errmsg = parse_vec48alubreg_h (cd, strp, VC4_OPERAND_V48BREG_H, (unsigned long *) (& fields->f_vec48breg));
      break;
    case VC4_OPERAND_V48BREG_V :
      errmsg = parse_vec48alubreg_v (cd, strp, VC4_OPERAND_V48BREG_V, (unsigned long *) (& fields->f_vec48breg));
      break;
    case VC4_OPERAND_V48DREG_H :
      errmsg = parse_vec48aludreg_h (cd, strp, VC4_OPERAND_V48DREG_H, (unsigned long *) (& fields->f_vec48dreg));
      break;
    case VC4_OPERAND_V48DREG_V :
      errmsg = parse_vec48aludreg_v (cd, strp, VC4_OPERAND_V48DREG_V, (unsigned long *) (& fields->f_vec48dreg));
      break;
    case VC4_OPERAND_V48IMM :
      errmsg = parse_uimm6 (cd, strp, VC4_OPERAND_V48IMM, (unsigned long *) (& fields->f_op37_32));
      break;
    case VC4_OPERAND_V48IMM_MODS :
      errmsg = parse_vec48imm_mods (cd, strp, VC4_OPERAND_V48IMM_MODS, (unsigned long *) (& fields->f_op41_38));
      break;
    case VC4_OPERAND_V48SCLR :
      errmsg = parse_vec48sclr (cd, strp, VC4_OPERAND_V48SCLR, (unsigned long *) (& fields->f_op37_32));
      break;
    case VC4_OPERAND_V80A32REG :
      errmsg = parse_vec80aluareg (cd, strp, VC4_OPERAND_V80A32REG, (unsigned long *) (& fields->f_vec80areg));
      break;
    case VC4_OPERAND_V80B32REG :
      errmsg = parse_vec80alubreg (cd, strp, VC4_OPERAND_V80B32REG, (unsigned long *) (& fields->f_vec80breg));
      break;
    case VC4_OPERAND_V80D32REG :
      errmsg = parse_vec80aludreg (cd, strp, VC4_OPERAND_V80D32REG, (unsigned long *) (& fields->f_vec80dreg));
      break;
    case VC4_OPERAND_V80IMM :
      errmsg = parse_imm16 (cd, strp, VC4_OPERAND_V80IMM, (long *) (& fields->f_vec80imm));
      break;
    case VC4_OPERAND_V80MODS :
      errmsg = parse_vec80mods (cd, strp, VC4_OPERAND_V80MODS, (unsigned long *) (& fields->f_vec80mods));
      break;
    case VC4_OPERAND_V80MODS_MEM :
      errmsg = parse_vec80mods_mem (cd, strp, VC4_OPERAND_V80MODS_MEM, (unsigned long *) (& fields->f_vec80mods_mem));
      break;
    case VC4_OPERAND_VEC_LDADDR :
      errmsg = parse_vec80ldaddr (cd, strp, VC4_OPERAND_VEC_LDADDR, (unsigned long *) (& fields->f_vec80ldaddr));
      break;
    case VC4_OPERAND_VEC_STADDR :
      errmsg = parse_vec80staddr (cd, strp, VC4_OPERAND_VEC_STADDR, (unsigned long *) (& fields->f_vec80staddr));
      break;
    case VC4_OPERAND_VMEMWIDTH :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_eltsize, & fields->f_op4_3);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while parsing.\n"), opindex);
      abort ();
  }

  return errmsg;
}

cgen_parse_fn * const vc4_cgen_parse_handlers[] = 
{
  parse_insn_normal,
};

void
vc4_cgen_init_asm (CGEN_CPU_DESC cd)
{
  vc4_cgen_init_opcode_table (cd);
  vc4_cgen_init_ibld_table (cd);
  cd->parse_handlers = & vc4_cgen_parse_handlers[0];
  cd->parse_operand = vc4_cgen_parse_operand;
#ifdef CGEN_ASM_INIT_HOOK
CGEN_ASM_INIT_HOOK
#endif
}



/* Regex construction routine.

   This translates an opcode syntax string into a regex string,
   by replacing any non-character syntax element (such as an
   opcode) with the pattern '.*'

   It then compiles the regex and stores it in the opcode, for
   later use by vc4_cgen_assemble_insn

   Returns NULL for success, an error message for failure.  */

char * 
vc4_cgen_build_insn_regex (CGEN_INSN *insn)
{  
  CGEN_OPCODE *opc = (CGEN_OPCODE *) CGEN_INSN_OPCODE (insn);
  const char *mnem = CGEN_INSN_MNEMONIC (insn);
  char rxbuf[CGEN_MAX_RX_ELEMENTS];
  char *rx = rxbuf;
  const CGEN_SYNTAX_CHAR_TYPE *syn;
  int reg_err;

  syn = CGEN_SYNTAX_STRING (CGEN_OPCODE_SYNTAX (opc));

  /* Mnemonics come first in the syntax string.  */
  if (! CGEN_SYNTAX_MNEMONIC_P (* syn))
    return _("missing mnemonic in syntax string");
  ++syn;

  /* Generate a case sensitive regular expression that emulates case
     insensitive matching in the "C" locale.  We cannot generate a case
     insensitive regular expression because in Turkish locales, 'i' and 'I'
     are not equal modulo case conversion.  */

  /* Copy the literal mnemonic out of the insn.  */
  for (; *mnem; mnem++)
    {
      char c = *mnem;

      if (ISALPHA (c))
	{
	  *rx++ = '[';
	  *rx++ = TOLOWER (c);
	  *rx++ = TOUPPER (c);
	  *rx++ = ']';
	}
      else
	*rx++ = c;
    }

  /* Copy any remaining literals from the syntax string into the rx.  */
  for(; * syn != 0 && rx <= rxbuf + (CGEN_MAX_RX_ELEMENTS - 7 - 4); ++syn)
    {
      if (CGEN_SYNTAX_CHAR_P (* syn)) 
	{
	  char c = CGEN_SYNTAX_CHAR (* syn);

	  switch (c) 
	    {
	      /* Escape any regex metacharacters in the syntax.  */
	    case '.': case '[': case '\\': 
	    case '*': case '^': case '$': 

#ifdef CGEN_ESCAPE_EXTENDED_REGEX
	    case '?': case '{': case '}': 
	    case '(': case ')': case '*':
	    case '|': case '+': case ']':
#endif
	      *rx++ = '\\';
	      *rx++ = c;
	      break;

	    default:
	      if (ISALPHA (c))
		{
		  *rx++ = '[';
		  *rx++ = TOLOWER (c);
		  *rx++ = TOUPPER (c);
		  *rx++ = ']';
		}
	      else
		*rx++ = c;
	      break;
	    }
	}
      else
	{
	  /* Replace non-syntax fields with globs.  */
	  *rx++ = '.';
	  *rx++ = '*';
	}
    }

  /* Trailing whitespace ok.  */
  * rx++ = '['; 
  * rx++ = ' '; 
  * rx++ = '\t'; 
  * rx++ = ']'; 
  * rx++ = '*'; 

  /* But anchor it after that.  */
  * rx++ = '$'; 
  * rx = '\0';

  CGEN_INSN_RX (insn) = xmalloc (sizeof (regex_t));
  reg_err = regcomp ((regex_t *) CGEN_INSN_RX (insn), rxbuf, REG_NOSUB);

  if (reg_err == 0) 
    return NULL;
  else
    {
      static char msg[80];

      regerror (reg_err, (regex_t *) CGEN_INSN_RX (insn), msg, 80);
      regfree ((regex_t *) CGEN_INSN_RX (insn));
      free (CGEN_INSN_RX (insn));
      (CGEN_INSN_RX (insn)) = NULL;
      return msg;
    }
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

const CGEN_INSN *vc4_cgen_assemble_insn_at (CGEN_CPU_DESC, const char *,
  CGEN_FIELDS *, CGEN_INSN_BYTES_PTR, bfd_vma, int, char **);

const CGEN_INSN *
vc4_cgen_assemble_insn (CGEN_CPU_DESC cd,
			   const char *str,
			   CGEN_FIELDS *fields,
			   CGEN_INSN_BYTES_PTR buf,
			   char **errmsg)
{
  return vc4_cgen_assemble_insn_at (cd, str, fields, buf, 0, 0, errmsg);
}

/* Same as vc4_cgen_assemble_insn, but pc relative operands are
   encoded relative to PC, and RELAXED insns (the wider forms gas picks
   when relaxing) are also accepted when RELAX is set.  */

const CGEN_INSN *
vc4_cgen_assemble_insn_at (CGEN_CPU_DESC cd,
			   const char *str,
			   CGEN_FIELDS *fields,
			   CGEN_INSN_BYTES_PTR buf,
			   bfd_vma pc,
			   int relax,
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
      if (! vc4_cgen_insn_supported (cd, insn))
	continue;
#endif
      /* If the RELAXED attribute is set, this is an insn that shouldn't be
	 chosen immediately.  Instead, it is used during assembler/linker
	 relaxation if possible.  */
      if (!relax && CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_RELAXED) != 0)
	continue;

      str = start;

      /* Skip this insn if str doesn't look right lexically.  */
      if (CGEN_INSN_RX (insn) != NULL &&
	  regexec ((regex_t *) CGEN_INSN_RX (insn), str, 0, NULL, 0) == REG_NOMATCH)
	continue;

      /* Allow parse/insert handlers to obtain length of insn.  */
      CGEN_FIELDS_BITSIZE (fields) = CGEN_INSN_BITSIZE (insn);

      parse_errmsg = CGEN_PARSE_FN (cd, insn) (cd, insn, & str, fields);
      if (parse_errmsg != NULL)
	continue;

      insert_errmsg = CGEN_INSERT_FN (cd, insn) (cd, insn, fields, buf, pc);
      if (insert_errmsg != NULL)
        continue;

      /* It is up to the caller to actually output the insn and any
         queued relocs.  */
      return insn;
    }

  {
    static char errbuf[150];
    const char *tmp_errmsg;
#ifndef CGEN_QUIET_ASSEMBLER_ERRORS
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
