/* Instruction building/extraction support for nios. -*- C -*-

THIS FILE IS MACHINE GENERATED WITH CGEN: Cpu tools GENerator.
- the resultant file is machine generated, cgen-ibld.in isn't

Copyright (C) 1996, 1997, 1998, 1999, 2000 Free Software Foundation, Inc.

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
#include <ctype.h>
#include <stdio.h>
#include "ansidecl.h"
#include "dis-asm.h"
#include "bfd.h"
#include "symcat.h"
#include "nios-desc.h"
#include "nios-opc.h"
#include "opintl.h"

#undef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#undef max
#define max(a,b) ((a) > (b) ? (a) : (b))

/* Used by the ifield rtx function.  */
#define FLD(f) (fields->f)

static const char * insert_normal
     PARAMS ((CGEN_CPU_DESC, long, unsigned int, unsigned int, unsigned int,
	      unsigned int, unsigned int, unsigned int, CGEN_INSN_BYTES_PTR));
static const char * insert_insn_normal
     PARAMS ((CGEN_CPU_DESC, const CGEN_INSN *,
	      CGEN_FIELDS *, CGEN_INSN_BYTES_PTR, bfd_vma));

static int extract_normal
     PARAMS ((CGEN_CPU_DESC, CGEN_EXTRACT_INFO *, CGEN_INSN_INT,
	      unsigned int, unsigned int, unsigned int, unsigned int,
	      unsigned int, unsigned int, bfd_vma, long *));
static int extract_insn_normal
     PARAMS ((CGEN_CPU_DESC, const CGEN_INSN *, CGEN_EXTRACT_INFO *,
	      CGEN_INSN_INT, CGEN_FIELDS *, bfd_vma));

/* Operand insertion.  */

#if ! CGEN_INT_INSN_P

/* Subroutine of insert_normal.  */

static CGEN_INLINE void
insert_1 (cd, value, start, length, word_length, bufp)
     CGEN_CPU_DESC cd;
     unsigned long value;
     int start,length,word_length;
     unsigned char *bufp;
{
  unsigned long x,mask;
  int shift;
  int big_p = CGEN_CPU_INSN_ENDIAN (cd) == CGEN_ENDIAN_BIG;

  switch (word_length)
    {
    case 8:
      x = *bufp;
      break;
    case 16:
      if (big_p)
	x = bfd_getb16 (bufp);
      else
	x = bfd_getl16 (bufp);
      break;
    case 24:
      /* ??? This may need reworking as these cases don't necessarily
	 want the first byte and the last two bytes handled like this.  */
      if (big_p)
	x = (bufp[0] << 16) | bfd_getb16 (bufp + 1);
      else
	x = bfd_getl16 (bufp) | (bufp[2] << 16);
      break;
    case 32:
      if (big_p)
	x = bfd_getb32 (bufp);
      else
	x = bfd_getl32 (bufp);
      break;
    default :
      abort ();
    }

  /* Written this way to avoid undefined behaviour.  */
  mask = (((1L << (length - 1)) - 1) << 1) | 1;
  if (CGEN_INSN_LSB0_P)
    shift = (start + 1) - length;
  else
    shift = (word_length - (start + length));
  x = (x & ~(mask << shift)) | ((value & mask) << shift);

  switch (word_length)
    {
    case 8:
      *bufp = x;
      break;
    case 16:
      if (big_p)
	bfd_putb16 (x, bufp);
      else
	bfd_putl16 (x, bufp);
      break;
    case 24:
      /* ??? This may need reworking as these cases don't necessarily
	 want the first byte and the last two bytes handled like this.  */
      if (big_p)
	{
	  bufp[0] = x >> 16;
	  bfd_putb16 (x, bufp + 1);
	}
      else
	{
	  bfd_putl16 (x, bufp);
	  bufp[2] = x >> 16;
	}
      break;
    case 32:
      if (big_p)
	bfd_putb32 (x, bufp);
      else
	bfd_putl32 (x, bufp);
      break;
    default :
      abort ();
    }
}

#endif /* ! CGEN_INT_INSN_P */

/* Default insertion routine.

   ATTRS is a mask of the boolean attributes.
   WORD_OFFSET is the offset in bits from the start of the insn of the value.
   WORD_LENGTH is the length of the word in bits in which the value resides.
   START is the starting bit number in the word, architecture origin.
   LENGTH is the length of VALUE in bits.
   TOTAL_LENGTH is the total length of the insn in bits.

   The result is an error message or NULL if success.  */

/* ??? This duplicates functionality with bfd's howto table and
   bfd_install_relocation.  */
/* ??? This doesn't handle bfd_vma's.  Create another function when
   necessary.  */

static const char *
insert_normal (cd, value, attrs, word_offset, start, length, word_length,
	       total_length, buffer)
     CGEN_CPU_DESC cd;
     long value;
     unsigned int attrs;
     unsigned int word_offset, start, length, word_length, total_length;
     CGEN_INSN_BYTES_PTR buffer;
{
  static char errbuf[100];
  /* Written this way to avoid undefined behaviour.  */
  unsigned long mask = (((1L << (length - 1)) - 1) << 1) | 1;

  /* If LENGTH is zero, this operand doesn't contribute to the value.  */
  if (length == 0)
    return NULL;

  if (CGEN_INT_INSN_P
      && word_offset != 0)
    abort ();

  if (word_length > 32)
    abort ();

  /* For architectures with insns smaller than the base-insn-bitsize,
     word_length may be too big.  */
  if (cd->min_insn_bitsize < cd->base_insn_bitsize)
    {
      if (word_offset == 0
	  && word_length > total_length)
	word_length = total_length;
    }

  /* Ensure VALUE will fit.  */
  if (! CGEN_BOOL_ATTR (attrs, CGEN_IFLD_SIGNED))
    {
      unsigned long maxval = mask;
      
      if ((unsigned long) value > maxval)
	{
	  /* xgettext:c-format */
	  sprintf (errbuf,
		   _("operand out of range (%lu not between 0 and %lu)"),
		   value, maxval);
	  return errbuf;
	}
    }
  else
    {
      if (! cgen_signed_overflow_ok_p (cd))
	{
	  long minval = - (1L << (length - 1));
	  long maxval =   (1L << (length - 1)) - 1;
	  
	  if (value < minval || value > maxval)
	    {
	      sprintf
		/* xgettext:c-format */
		(errbuf, _("operand out of range (%ld not between %ld and %ld)"),
		 value, minval, maxval);
	      return errbuf;
	    }
	}
    }

#if CGEN_INT_INSN_P

  {
    int shift;

    if (CGEN_INSN_LSB0_P)
      shift = (start + 1) - length;
    else
      shift = word_length - (start + length);
    *buffer = (*buffer & ~(mask << shift)) | ((value & mask) << shift);
  }

#else /* ! CGEN_INT_INSN_P */

  {
    unsigned char *bufp = (unsigned char *) buffer + word_offset / 8;

    insert_1 (cd, value, start, length, word_length, bufp);
  }

#endif /* ! CGEN_INT_INSN_P */

  return NULL;
}

/* Default insn builder (insert handler).
   The instruction is recorded in CGEN_INT_INSN_P byte order
   (meaning that if CGEN_INT_INSN_P BUFFER is an int * and thus the value is
   recorded in host byte order, otherwise BUFFER is an array of bytes and the
   value is recorded in target byte order).
   The result is an error message or NULL if success.  */

static const char *
insert_insn_normal (cd, insn, fields, buffer, pc)
     CGEN_CPU_DESC cd;
     const CGEN_INSN * insn;
     CGEN_FIELDS * fields;
     CGEN_INSN_BYTES_PTR buffer;
     bfd_vma pc;
{
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  unsigned long value;
  const unsigned char * syn;

  CGEN_INIT_INSERT (cd);
  value = CGEN_INSN_BASE_VALUE (insn);

  /* If we're recording insns as numbers (rather than a string of bytes),
     target byte order handling is deferred until later.  */

#if CGEN_INT_INSN_P

  *buffer = value;

#else

  cgen_put_insn_value (cd, buffer, min (cd->base_insn_bitsize,
					CGEN_FIELDS_BITSIZE (fields)),
		       value);

#endif /* ! CGEN_INT_INSN_P */

  /* ??? It would be better to scan the format's fields.
     Still need to be able to insert a value based on the operand though;
     e.g. storing a branch displacement that got resolved later.
     Needs more thought first.  */

  for (syn = CGEN_SYNTAX_STRING (syntax); * syn != '\0'; ++ syn)
    {
      const char *errmsg;

      if (CGEN_SYNTAX_CHAR_P (* syn))
	continue;

      errmsg = (* cd->insert_operand) (cd, CGEN_SYNTAX_FIELD (*syn),
				       fields, buffer, pc);
      if (errmsg)
	return errmsg;
    }

  return NULL;
}

/* Operand extraction.  */

#if ! CGEN_INT_INSN_P

/* Subroutine of extract_normal.
   Ensure sufficient bytes are cached in EX_INFO.
   OFFSET is the offset in bytes from the start of the insn of the value.
   BYTES is the length of the needed value.
   Returns 1 for success, 0 for failure.  */

static CGEN_INLINE int
fill_cache (cd, ex_info, offset, bytes, pc)
     CGEN_CPU_DESC cd;
     CGEN_EXTRACT_INFO *ex_info;
     int offset, bytes;
     bfd_vma pc;
{
  /* It's doubtful that the middle part has already been fetched so
     we don't optimize that case.  kiss.  */
  int mask;
  disassemble_info *info = (disassemble_info *) ex_info->dis_info;

  /* First do a quick check.  */
  mask = (1 << bytes) - 1;
  if (((ex_info->valid >> offset) & mask) == mask)
    return 1;

  /* Search for the first byte we need to read.  */
  for (mask = 1 << offset; bytes > 0; --bytes, ++offset, mask <<= 1)
    if (! (mask & ex_info->valid))
      break;

  if (bytes)
    {
      int status;

      pc += offset;
      status = (*info->read_memory_func)
	(pc, ex_info->insn_bytes + offset, bytes, info);

      if (status != 0)
	{
	  (*info->memory_error_func) (status, pc, info);
	  return 0;
	}

      ex_info->valid |= ((1 << bytes) - 1) << offset;
    }

  return 1;
}

/* Subroutine of extract_normal.  */

static CGEN_INLINE long
extract_1 (cd, ex_info, start, length, word_length, bufp, pc)
     CGEN_CPU_DESC cd;
     CGEN_EXTRACT_INFO *ex_info;
     int start,length,word_length;
     unsigned char *bufp;
     bfd_vma pc;
{
  unsigned long x,mask;
  int shift;
  int big_p = CGEN_CPU_INSN_ENDIAN (cd) == CGEN_ENDIAN_BIG;

  switch (word_length)
    {
    case 8:
      x = *bufp;
      break;
    case 16:
      if (big_p)
	x = bfd_getb16 (bufp);
      else
	x = bfd_getl16 (bufp);
      break;
    case 24:
      /* ??? This may need reworking as these cases don't necessarily
	 want the first byte and the last two bytes handled like this.  */
      if (big_p)
	x = (bufp[0] << 16) | bfd_getb16 (bufp + 1);
      else
	x = bfd_getl16 (bufp) | (bufp[2] << 16);
      break;
    case 32:
      if (big_p)
	x = bfd_getb32 (bufp);
      else
	x = bfd_getl32 (bufp);
      break;
    default :
      abort ();
    }

  /* Written this way to avoid undefined behaviour.  */
  mask = (((1L << (length - 1)) - 1) << 1) | 1;
  if (CGEN_INSN_LSB0_P)
    shift = (start + 1) - length;
  else
    shift = (word_length - (start + length));
  return (x >> shift) & mask;
}

#endif /* ! CGEN_INT_INSN_P */

/* Default extraction routine.

   INSN_VALUE is the first base_insn_bitsize bits of the insn in host order,
   or sometimes less for cases like the m32r where the base insn size is 32
   but some insns are 16 bits.
   ATTRS is a mask of the boolean attributes.  We only need `SIGNED',
   but for generality we take a bitmask of all of them.
   WORD_OFFSET is the offset in bits from the start of the insn of the value.
   WORD_LENGTH is the length of the word in bits in which the value resides.
   START is the starting bit number in the word, architecture origin.
   LENGTH is the length of VALUE in bits.
   TOTAL_LENGTH is the total length of the insn in bits.

   Returns 1 for success, 0 for failure.  */

/* ??? The return code isn't properly used.  wip.  */

/* ??? This doesn't handle bfd_vma's.  Create another function when
   necessary.  */

static int
extract_normal (cd, ex_info, insn_value, attrs, word_offset, start, length,
		word_length, total_length, pc, valuep)
     CGEN_CPU_DESC cd;
     CGEN_EXTRACT_INFO *ex_info;
     CGEN_INSN_INT insn_value;
     unsigned int attrs;
     unsigned int word_offset, start, length, word_length, total_length;
     bfd_vma pc;
     long *valuep;
{
  CGEN_INSN_INT value;

  /* If LENGTH is zero, this operand doesn't contribute to the value
     so give it a standard value of zero.  */
  if (length == 0)
    {
      *valuep = 0;
      return 1;
    }

  if (CGEN_INT_INSN_P
      && word_offset != 0)
    abort ();

  if (word_length > 32)
    abort ();

  /* For architectures with insns smaller than the insn-base-bitsize,
     word_length may be too big.  */
  if (cd->min_insn_bitsize < cd->base_insn_bitsize)
    {
      if (word_offset == 0
	  && word_length > total_length)
	word_length = total_length;
    }

  /* Does the value reside in INSN_VALUE?  */

  if (word_offset == 0)
    {
      /* Written this way to avoid undefined behaviour.  */
      CGEN_INSN_INT mask = (((1L << (length - 1)) - 1) << 1) | 1;

      if (CGEN_INSN_LSB0_P)
	value = insn_value >> ((start + 1) - length);
      else
	value = insn_value >> (word_length - (start + length));
      value &= mask;
      /* sign extend? */
      if (CGEN_BOOL_ATTR (attrs, CGEN_IFLD_SIGNED)
	  && (value & (1L << (length - 1))))
	value |= ~mask;
    }

#if ! CGEN_INT_INSN_P

  else
    {
      unsigned char *bufp = ex_info->insn_bytes + word_offset / 8;

      if (word_length > 32)
	abort ();

      if (fill_cache (cd, ex_info, word_offset / 8, word_length / 8, pc) == 0)
	return 0;

      value = extract_1 (cd, ex_info, start, length, word_length, bufp, pc);
    }

#endif /* ! CGEN_INT_INSN_P */

  *valuep = value;

  return 1;
}

/* Default insn extractor.

   INSN_VALUE is the first base_insn_bitsize bits, translated to host order.
   The extracted fields are stored in FIELDS.
   EX_INFO is used to handle reading variable length insns.
   Return the length of the insn in bits, or 0 if no match,
   or -1 if an error occurs fetching data (memory_error_func will have
   been called).  */

static int
extract_insn_normal (cd, insn, ex_info, insn_value, fields, pc)
     CGEN_CPU_DESC cd;
     const CGEN_INSN *insn;
     CGEN_EXTRACT_INFO *ex_info;
     CGEN_INSN_INT insn_value;
     CGEN_FIELDS *fields;
     bfd_vma pc;
{
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  const unsigned char *syn;

  CGEN_FIELDS_BITSIZE (fields) = CGEN_INSN_BITSIZE (insn);

  CGEN_INIT_EXTRACT (cd);

  for (syn = CGEN_SYNTAX_STRING (syntax); *syn; ++syn)
    {
      int length;

      if (CGEN_SYNTAX_CHAR_P (*syn))
	continue;

      length = (* cd->extract_operand) (cd, CGEN_SYNTAX_FIELD (*syn),
					ex_info, insn_value, fields, pc);
      if (length <= 0)
	return length;
    }

  /* We recognized and successfully extracted this insn.  */
  return CGEN_INSN_BITSIZE (insn);
}

/* machine generated code added here */

/* Main entry point for operand insertion.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `parse_insn_normal', but keeping it
   separate makes clear the interface between `parse_insn_normal' and each of
   the handlers.  It's also needed by GAS to insert operands that couldn't be
   resolved during parsing.
*/

const char *
nios_cgen_insert_operand (cd, opindex, fields, buffer, pc)
     CGEN_CPU_DESC cd;
     int opindex;
     CGEN_FIELDS * fields;
     CGEN_INSN_BYTES_PTR buffer;
     bfd_vma pc;
{
  const char * errmsg = NULL;
  unsigned int total_length = CGEN_FIELDS_BITSIZE (fields);

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      errmsg = insert_normal (cd, fields->f_CTLc, 0, 0, 4, 3, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_RBI5 :
      errmsg = insert_normal (cd, fields->f_Rbi5, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      {
        long value = fields->f_bsrr_i6_rel;
        value = ((value) - (pc));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_I1 :
      {
        long value = fields->f_i1;
        value = ((value) << (1));
        errmsg = insert_normal (cd, value, 0, 0, 6, 2, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_I10 :
      errmsg = insert_normal (cd, fields->f_i10, 0, 0, 9, 10, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I11 :
      errmsg = insert_normal (cd, fields->f_i11, 0, 0, 10, 11, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I2 :
      errmsg = insert_normal (cd, fields->f_i2, 0, 0, 6, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I4W :
      errmsg = insert_normal (cd, fields->f_i4w, 0, 0, 3, 4, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I4WN :
      errmsg = insert_normal (cd, fields->f_i4w, 0, 0, 3, 4, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I5 :
      errmsg = insert_normal (cd, fields->f_i5, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I6V :
      errmsg = insert_normal (cd, fields->f_i6v, 0, 0, 5, 6, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I8 :
      errmsg = insert_normal (cd, fields->f_i8, 0, 0, 12, 8, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I8V :
      errmsg = insert_normal (cd, fields->f_i8v, 0, 0, 7, 8, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_I9 :
      errmsg = insert_normal (cd, fields->f_i9, 0, 0, 9, 9, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M16_R0 :
      break;
    case NIOS_OPERAND_M16_RA :
      errmsg = insert_normal (cd, fields->f_Ra, 0, 0, 4, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M16_RB :
      errmsg = insert_normal (cd, fields->f_Rb, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M16_RP :
      errmsg = insert_normal (cd, fields->f_Rp, 0, 0, 11, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M16_RZ :
      errmsg = insert_normal (cd, fields->f_Rz, 0, 0, 1, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M16_I6 :
      {
        long value = fields->f_i6_rel_h;
        value = (((((value) | (pc))) == (0))) ? (0) : (((((unsigned int) (((value) - (pc))) >> (1))) - (2)));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_M16_I8V :
      {
        long value = fields->f_i8v_rel_h;
        value = (((((value) | (pc))) == (0))) ? (0) : (((((unsigned int) (((value) - (pc))) >> (1))) - (1)));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 7, 8, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_M16_SP :
      break;
    case NIOS_OPERAND_M32_R0 :
      break;
    case NIOS_OPERAND_M32_RA :
      errmsg = insert_normal (cd, fields->f_Ra, 0, 0, 4, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M32_RB :
      errmsg = insert_normal (cd, fields->f_Rb, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M32_RP :
      errmsg = insert_normal (cd, fields->f_Rp, 0, 0, 11, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M32_RZ :
      errmsg = insert_normal (cd, fields->f_Rz, 0, 0, 1, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_M32_I6 :
      {
        long value = fields->f_i6_rel_w;
        value = (((((value) | (pc))) == (0))) ? (0) : (((((unsigned int) (((value) - (pc))) >> (2))) - (1)));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_M32_I8V :
      {
        long value = fields->f_i8v_rel_w;
        value = (((((value) | (pc))) == (0))) ? (0) : (((((unsigned int) (((value) - (pc))) >> (1))) - (1)));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 7, 8, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_M32_SP :
      break;
    case NIOS_OPERAND_O1 :
      errmsg = insert_normal (cd, fields->f_o1, 0, 0, 5, 1, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_O2 :
      errmsg = insert_normal (cd, fields->f_o2, 0, 0, 7, 2, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_REL11 :
      {
        long value = fields->f_i11_rel;
        value = ((((int) (((value) - (pc))) >> (1))) - (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 11, 16, total_length, buffer);
      }
      break;
    case NIOS_OPERAND_SAVE_I8V :
      errmsg = insert_normal (cd, fields->f_i8v, 0, 0, 7, 8, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_SI11 :
      errmsg = insert_normal (cd, fields->f_i11, 0, 0, 10, 11, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_SI5 :
      errmsg = insert_normal (cd, fields->f_i5, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_X1 :
      errmsg = insert_normal (cd, fields->f_x1, 0, 0, 4, 1, 16, total_length, buffer);
      break;
    case NIOS_OPERAND_XRA :
      errmsg = insert_normal (cd, fields->f_Ra, 0, 0, 4, 5, 16, total_length, buffer);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while building insn.\n"),
	       opindex);
      abort ();
  }

  return errmsg;
}

/* Main entry point for operand extraction.
   The result is <= 0 for error, >0 for success.
   ??? Actual values aren't well defined right now.

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

int
nios_cgen_extract_operand (cd, opindex, ex_info, insn_value, fields, pc)
     CGEN_CPU_DESC cd;
     int opindex;
     CGEN_EXTRACT_INFO *ex_info;
     CGEN_INSN_INT insn_value;
     CGEN_FIELDS * fields;
     bfd_vma pc;
{
  /* Assume success (for those operands that are nops).  */
  int length = 1;
  unsigned int total_length = CGEN_FIELDS_BITSIZE (fields);

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 3, 16, total_length, pc, & fields->f_CTLc);
      break;
    case NIOS_OPERAND_RBI5 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_Rbi5);
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, pc, & value);
        value = ((pc) + (value));
        fields->f_bsrr_i6_rel = value;
      }
      break;
    case NIOS_OPERAND_I1 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 6, 2, 16, total_length, pc, & value);
        value = ((unsigned int) (value) >> (1));
        fields->f_i1 = value;
      }
      break;
    case NIOS_OPERAND_I10 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 10, 16, total_length, pc, & fields->f_i10);
      break;
    case NIOS_OPERAND_I11 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 11, 16, total_length, pc, & fields->f_i11);
      break;
    case NIOS_OPERAND_I2 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 6, 2, 16, total_length, pc, & fields->f_i2);
      break;
    case NIOS_OPERAND_I4W :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 3, 4, 16, total_length, pc, & fields->f_i4w);
      break;
    case NIOS_OPERAND_I4WN :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 3, 4, 16, total_length, pc, & fields->f_i4w);
      break;
    case NIOS_OPERAND_I5 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_i5);
      break;
    case NIOS_OPERAND_I6V :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 5, 6, 16, total_length, pc, & fields->f_i6v);
      break;
    case NIOS_OPERAND_I8 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 12, 8, 16, total_length, pc, & fields->f_i8);
      break;
    case NIOS_OPERAND_I8V :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 8, 16, total_length, pc, & fields->f_i8v);
      break;
    case NIOS_OPERAND_I9 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 9, 16, total_length, pc, & fields->f_i9);
      break;
    case NIOS_OPERAND_M16_R0 :
      break;
    case NIOS_OPERAND_M16_RA :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & fields->f_Ra);
      break;
    case NIOS_OPERAND_M16_RB :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_Rb);
      break;
    case NIOS_OPERAND_M16_RP :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 11, 2, 16, total_length, pc, & fields->f_Rp);
      break;
    case NIOS_OPERAND_M16_RZ :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 1, 2, 16, total_length, pc, & fields->f_Rz);
      break;
    case NIOS_OPERAND_M16_I6 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, pc, & value);
        value = ((((value) << (1))) + (((((pc) & (131070))) + (4))));
        fields->f_i6_rel_h = value;
      }
      break;
    case NIOS_OPERAND_M16_I8V :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 7, 8, 16, total_length, pc, & value);
        value = ((((value) << (1))) + (((((pc) & (131070))) + (2))));
        fields->f_i8v_rel_h = value;
      }
      break;
    case NIOS_OPERAND_M16_SP :
      break;
    case NIOS_OPERAND_M32_R0 :
      break;
    case NIOS_OPERAND_M32_RA :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & fields->f_Ra);
      break;
    case NIOS_OPERAND_M32_RB :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_Rb);
      break;
    case NIOS_OPERAND_M32_RP :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 11, 2, 16, total_length, pc, & fields->f_Rp);
      break;
    case NIOS_OPERAND_M32_RZ :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 1, 2, 16, total_length, pc, & fields->f_Rz);
      break;
    case NIOS_OPERAND_M32_I6 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 6, 16, total_length, pc, & value);
        value = ((((value) << (2))) + (((((pc) & (0xfffffffc))) + (4))));
        fields->f_i6_rel_w = value;
      }
      break;
    case NIOS_OPERAND_M32_I8V :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_PCREL_ADDR), 0, 7, 8, 16, total_length, pc, & value);
        value = ((((((value) << (1))) + (((pc) + (2))))) & (0xfffffffc));
        fields->f_i8v_rel_w = value;
      }
      break;
    case NIOS_OPERAND_M32_SP :
      break;
    case NIOS_OPERAND_O1 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 5, 1, 16, total_length, pc, & fields->f_o1);
      break;
    case NIOS_OPERAND_O2 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 2, 16, total_length, pc, & fields->f_o2);
      break;
    case NIOS_OPERAND_REL11 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 0, 10, 11, 16, total_length, pc, & value);
        value = ((((((value) << (1))) + (pc))) + (2));
        fields->f_i11_rel = value;
      }
      break;
    case NIOS_OPERAND_SAVE_I8V :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 8, 16, total_length, pc, & fields->f_i8v);
      break;
    case NIOS_OPERAND_SI11 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 11, 16, total_length, pc, & fields->f_i11);
      break;
    case NIOS_OPERAND_SI5 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_i5);
      break;
    case NIOS_OPERAND_X1 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 1, 16, total_length, pc, & fields->f_x1);
      break;
    case NIOS_OPERAND_XRA :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & fields->f_Ra);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while decoding insn.\n"),
	       opindex);
      abort ();
    }

  return length;
}

cgen_insert_fn * const nios_cgen_insert_handlers[] = 
{
  insert_insn_normal,
};

cgen_extract_fn * const nios_cgen_extract_handlers[] = 
{
  extract_insn_normal,
};

/* Getting values from cgen_fields is handled by a collection of functions.
   They are distinguished by the type of the VALUE argument they return.
   TODO: floating point, inlining support, remove cases where result type
   not appropriate.  */

int
nios_cgen_get_int_operand (cd, opindex, fields)
     CGEN_CPU_DESC cd;
     int opindex;
     const CGEN_FIELDS * fields;
{
  int value;

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      value = fields->f_CTLc;
      break;
    case NIOS_OPERAND_RBI5 :
      value = fields->f_Rbi5;
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      value = fields->f_bsrr_i6_rel;
      break;
    case NIOS_OPERAND_I1 :
      value = fields->f_i1;
      break;
    case NIOS_OPERAND_I10 :
      value = fields->f_i10;
      break;
    case NIOS_OPERAND_I11 :
      value = fields->f_i11;
      break;
    case NIOS_OPERAND_I2 :
      value = fields->f_i2;
      break;
    case NIOS_OPERAND_I4W :
      value = fields->f_i4w;
      break;
    case NIOS_OPERAND_I4WN :
      value = fields->f_i4w;
      break;
    case NIOS_OPERAND_I5 :
      value = fields->f_i5;
      break;
    case NIOS_OPERAND_I6V :
      value = fields->f_i6v;
      break;
    case NIOS_OPERAND_I8 :
      value = fields->f_i8;
      break;
    case NIOS_OPERAND_I8V :
      value = fields->f_i8v;
      break;
    case NIOS_OPERAND_I9 :
      value = fields->f_i9;
      break;
    case NIOS_OPERAND_M16_R0 :
      value = 0;
      break;
    case NIOS_OPERAND_M16_RA :
      value = fields->f_Ra;
      break;
    case NIOS_OPERAND_M16_RB :
      value = fields->f_Rb;
      break;
    case NIOS_OPERAND_M16_RP :
      value = fields->f_Rp;
      break;
    case NIOS_OPERAND_M16_RZ :
      value = fields->f_Rz;
      break;
    case NIOS_OPERAND_M16_I6 :
      value = fields->f_i6_rel_h;
      break;
    case NIOS_OPERAND_M16_I8V :
      value = fields->f_i8v_rel_h;
      break;
    case NIOS_OPERAND_M16_SP :
      value = 0;
      break;
    case NIOS_OPERAND_M32_R0 :
      value = 0;
      break;
    case NIOS_OPERAND_M32_RA :
      value = fields->f_Ra;
      break;
    case NIOS_OPERAND_M32_RB :
      value = fields->f_Rb;
      break;
    case NIOS_OPERAND_M32_RP :
      value = fields->f_Rp;
      break;
    case NIOS_OPERAND_M32_RZ :
      value = fields->f_Rz;
      break;
    case NIOS_OPERAND_M32_I6 :
      value = fields->f_i6_rel_w;
      break;
    case NIOS_OPERAND_M32_I8V :
      value = fields->f_i8v_rel_w;
      break;
    case NIOS_OPERAND_M32_SP :
      value = 0;
      break;
    case NIOS_OPERAND_O1 :
      value = fields->f_o1;
      break;
    case NIOS_OPERAND_O2 :
      value = fields->f_o2;
      break;
    case NIOS_OPERAND_REL11 :
      value = fields->f_i11_rel;
      break;
    case NIOS_OPERAND_SAVE_I8V :
      value = fields->f_i8v;
      break;
    case NIOS_OPERAND_SI11 :
      value = fields->f_i11;
      break;
    case NIOS_OPERAND_SI5 :
      value = fields->f_i5;
      break;
    case NIOS_OPERAND_X1 :
      value = fields->f_x1;
      break;
    case NIOS_OPERAND_XRA :
      value = fields->f_Ra;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while getting int operand.\n"),
		       opindex);
      abort ();
  }

  return value;
}

bfd_vma
nios_cgen_get_vma_operand (cd, opindex, fields)
     CGEN_CPU_DESC cd;
     int opindex;
     const CGEN_FIELDS * fields;
{
  bfd_vma value;

  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      value = fields->f_CTLc;
      break;
    case NIOS_OPERAND_RBI5 :
      value = fields->f_Rbi5;
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      value = fields->f_bsrr_i6_rel;
      break;
    case NIOS_OPERAND_I1 :
      value = fields->f_i1;
      break;
    case NIOS_OPERAND_I10 :
      value = fields->f_i10;
      break;
    case NIOS_OPERAND_I11 :
      value = fields->f_i11;
      break;
    case NIOS_OPERAND_I2 :
      value = fields->f_i2;
      break;
    case NIOS_OPERAND_I4W :
      value = fields->f_i4w;
      break;
    case NIOS_OPERAND_I4WN :
      value = fields->f_i4w;
      break;
    case NIOS_OPERAND_I5 :
      value = fields->f_i5;
      break;
    case NIOS_OPERAND_I6V :
      value = fields->f_i6v;
      break;
    case NIOS_OPERAND_I8 :
      value = fields->f_i8;
      break;
    case NIOS_OPERAND_I8V :
      value = fields->f_i8v;
      break;
    case NIOS_OPERAND_I9 :
      value = fields->f_i9;
      break;
    case NIOS_OPERAND_M16_R0 :
      value = 0;
      break;
    case NIOS_OPERAND_M16_RA :
      value = fields->f_Ra;
      break;
    case NIOS_OPERAND_M16_RB :
      value = fields->f_Rb;
      break;
    case NIOS_OPERAND_M16_RP :
      value = fields->f_Rp;
      break;
    case NIOS_OPERAND_M16_RZ :
      value = fields->f_Rz;
      break;
    case NIOS_OPERAND_M16_I6 :
      value = fields->f_i6_rel_h;
      break;
    case NIOS_OPERAND_M16_I8V :
      value = fields->f_i8v_rel_h;
      break;
    case NIOS_OPERAND_M16_SP :
      value = 0;
      break;
    case NIOS_OPERAND_M32_R0 :
      value = 0;
      break;
    case NIOS_OPERAND_M32_RA :
      value = fields->f_Ra;
      break;
    case NIOS_OPERAND_M32_RB :
      value = fields->f_Rb;
      break;
    case NIOS_OPERAND_M32_RP :
      value = fields->f_Rp;
      break;
    case NIOS_OPERAND_M32_RZ :
      value = fields->f_Rz;
      break;
    case NIOS_OPERAND_M32_I6 :
      value = fields->f_i6_rel_w;
      break;
    case NIOS_OPERAND_M32_I8V :
      value = fields->f_i8v_rel_w;
      break;
    case NIOS_OPERAND_M32_SP :
      value = 0;
      break;
    case NIOS_OPERAND_O1 :
      value = fields->f_o1;
      break;
    case NIOS_OPERAND_O2 :
      value = fields->f_o2;
      break;
    case NIOS_OPERAND_REL11 :
      value = fields->f_i11_rel;
      break;
    case NIOS_OPERAND_SAVE_I8V :
      value = fields->f_i8v;
      break;
    case NIOS_OPERAND_SI11 :
      value = fields->f_i11;
      break;
    case NIOS_OPERAND_SI5 :
      value = fields->f_i5;
      break;
    case NIOS_OPERAND_X1 :
      value = fields->f_x1;
      break;
    case NIOS_OPERAND_XRA :
      value = fields->f_Ra;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while getting vma operand.\n"),
		       opindex);
      abort ();
  }

  return value;
}

/* Stuffing values in cgen_fields is handled by a collection of functions.
   They are distinguished by the type of the VALUE argument they accept.
   TODO: floating point, inlining support, remove cases where argument type
   not appropriate.  */

void
nios_cgen_set_int_operand (cd, opindex, fields, value)
     CGEN_CPU_DESC cd;
     int opindex;
     CGEN_FIELDS * fields;
     int value;
{
  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      fields->f_CTLc = value;
      break;
    case NIOS_OPERAND_RBI5 :
      fields->f_Rbi5 = value;
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      fields->f_bsrr_i6_rel = value;
      break;
    case NIOS_OPERAND_I1 :
      fields->f_i1 = value;
      break;
    case NIOS_OPERAND_I10 :
      fields->f_i10 = value;
      break;
    case NIOS_OPERAND_I11 :
      fields->f_i11 = value;
      break;
    case NIOS_OPERAND_I2 :
      fields->f_i2 = value;
      break;
    case NIOS_OPERAND_I4W :
      fields->f_i4w = value;
      break;
    case NIOS_OPERAND_I4WN :
      fields->f_i4w = value;
      break;
    case NIOS_OPERAND_I5 :
      fields->f_i5 = value;
      break;
    case NIOS_OPERAND_I6V :
      fields->f_i6v = value;
      break;
    case NIOS_OPERAND_I8 :
      fields->f_i8 = value;
      break;
    case NIOS_OPERAND_I8V :
      fields->f_i8v = value;
      break;
    case NIOS_OPERAND_I9 :
      fields->f_i9 = value;
      break;
    case NIOS_OPERAND_M16_R0 :
      break;
    case NIOS_OPERAND_M16_RA :
      fields->f_Ra = value;
      break;
    case NIOS_OPERAND_M16_RB :
      fields->f_Rb = value;
      break;
    case NIOS_OPERAND_M16_RP :
      fields->f_Rp = value;
      break;
    case NIOS_OPERAND_M16_RZ :
      fields->f_Rz = value;
      break;
    case NIOS_OPERAND_M16_I6 :
      fields->f_i6_rel_h = value;
      break;
    case NIOS_OPERAND_M16_I8V :
      fields->f_i8v_rel_h = value;
      break;
    case NIOS_OPERAND_M16_SP :
      break;
    case NIOS_OPERAND_M32_R0 :
      break;
    case NIOS_OPERAND_M32_RA :
      fields->f_Ra = value;
      break;
    case NIOS_OPERAND_M32_RB :
      fields->f_Rb = value;
      break;
    case NIOS_OPERAND_M32_RP :
      fields->f_Rp = value;
      break;
    case NIOS_OPERAND_M32_RZ :
      fields->f_Rz = value;
      break;
    case NIOS_OPERAND_M32_I6 :
      fields->f_i6_rel_w = value;
      break;
    case NIOS_OPERAND_M32_I8V :
      fields->f_i8v_rel_w = value;
      break;
    case NIOS_OPERAND_M32_SP :
      break;
    case NIOS_OPERAND_O1 :
      fields->f_o1 = value;
      break;
    case NIOS_OPERAND_O2 :
      fields->f_o2 = value;
      break;
    case NIOS_OPERAND_REL11 :
      fields->f_i11_rel = value;
      break;
    case NIOS_OPERAND_SAVE_I8V :
      fields->f_i8v = value;
      break;
    case NIOS_OPERAND_SI11 :
      fields->f_i11 = value;
      break;
    case NIOS_OPERAND_SI5 :
      fields->f_i5 = value;
      break;
    case NIOS_OPERAND_X1 :
      fields->f_x1 = value;
      break;
    case NIOS_OPERAND_XRA :
      fields->f_Ra = value;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while setting int operand.\n"),
		       opindex);
      abort ();
  }
}

void
nios_cgen_set_vma_operand (cd, opindex, fields, value)
     CGEN_CPU_DESC cd;
     int opindex;
     CGEN_FIELDS * fields;
     bfd_vma value;
{
  switch (opindex)
    {
    case NIOS_OPERAND_CTLC :
      fields->f_CTLc = value;
      break;
    case NIOS_OPERAND_RBI5 :
      fields->f_Rbi5 = value;
      break;
    case NIOS_OPERAND_BSRR_REL6 :
      fields->f_bsrr_i6_rel = value;
      break;
    case NIOS_OPERAND_I1 :
      fields->f_i1 = value;
      break;
    case NIOS_OPERAND_I10 :
      fields->f_i10 = value;
      break;
    case NIOS_OPERAND_I11 :
      fields->f_i11 = value;
      break;
    case NIOS_OPERAND_I2 :
      fields->f_i2 = value;
      break;
    case NIOS_OPERAND_I4W :
      fields->f_i4w = value;
      break;
    case NIOS_OPERAND_I4WN :
      fields->f_i4w = value;
      break;
    case NIOS_OPERAND_I5 :
      fields->f_i5 = value;
      break;
    case NIOS_OPERAND_I6V :
      fields->f_i6v = value;
      break;
    case NIOS_OPERAND_I8 :
      fields->f_i8 = value;
      break;
    case NIOS_OPERAND_I8V :
      fields->f_i8v = value;
      break;
    case NIOS_OPERAND_I9 :
      fields->f_i9 = value;
      break;
    case NIOS_OPERAND_M16_R0 :
      break;
    case NIOS_OPERAND_M16_RA :
      fields->f_Ra = value;
      break;
    case NIOS_OPERAND_M16_RB :
      fields->f_Rb = value;
      break;
    case NIOS_OPERAND_M16_RP :
      fields->f_Rp = value;
      break;
    case NIOS_OPERAND_M16_RZ :
      fields->f_Rz = value;
      break;
    case NIOS_OPERAND_M16_I6 :
      fields->f_i6_rel_h = value;
      break;
    case NIOS_OPERAND_M16_I8V :
      fields->f_i8v_rel_h = value;
      break;
    case NIOS_OPERAND_M16_SP :
      break;
    case NIOS_OPERAND_M32_R0 :
      break;
    case NIOS_OPERAND_M32_RA :
      fields->f_Ra = value;
      break;
    case NIOS_OPERAND_M32_RB :
      fields->f_Rb = value;
      break;
    case NIOS_OPERAND_M32_RP :
      fields->f_Rp = value;
      break;
    case NIOS_OPERAND_M32_RZ :
      fields->f_Rz = value;
      break;
    case NIOS_OPERAND_M32_I6 :
      fields->f_i6_rel_w = value;
      break;
    case NIOS_OPERAND_M32_I8V :
      fields->f_i8v_rel_w = value;
      break;
    case NIOS_OPERAND_M32_SP :
      break;
    case NIOS_OPERAND_O1 :
      fields->f_o1 = value;
      break;
    case NIOS_OPERAND_O2 :
      fields->f_o2 = value;
      break;
    case NIOS_OPERAND_REL11 :
      fields->f_i11_rel = value;
      break;
    case NIOS_OPERAND_SAVE_I8V :
      fields->f_i8v = value;
      break;
    case NIOS_OPERAND_SI11 :
      fields->f_i11 = value;
      break;
    case NIOS_OPERAND_SI5 :
      fields->f_i5 = value;
      break;
    case NIOS_OPERAND_X1 :
      fields->f_x1 = value;
      break;
    case NIOS_OPERAND_XRA :
      fields->f_Ra = value;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while setting vma operand.\n"),
		       opindex);
      abort ();
  }
}

/* Function to call before using the instruction builder tables.  */

void
nios_cgen_init_ibld_table (cd)
     CGEN_CPU_DESC cd;
{
  cd->insert_handlers = & nios_cgen_insert_handlers[0];
  cd->extract_handlers = & nios_cgen_extract_handlers[0];

  cd->insert_operand = nios_cgen_insert_operand;
  cd->extract_operand = nios_cgen_extract_operand;

  cd->get_int_operand = nios_cgen_get_int_operand;
  cd->set_int_operand = nios_cgen_set_int_operand;
  cd->get_vma_operand = nios_cgen_get_vma_operand;
  cd->set_vma_operand = nios_cgen_set_vma_operand;
}
