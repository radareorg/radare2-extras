/* NIOS ELF support for BFD.
   Copyright (C) 1998 Free Software Foundation, Inc.

This file is part of BFD, the Binary File Descriptor library.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef _ELF_NIOS_H
#define _ELF_NIOS_H

#include "elf/reloc-macros.h"

/* Relocations.  */
START_RELOC_NUMBERS (elf_nios_reloc_type)
  RELOC_NUMBER (R_NIOS_NONE, 0)
  RELOC_NUMBER (R_NIOS_32, 1)
  RELOC_NUMBER (R_NIOS_LO16_LO5, 2)
  RELOC_NUMBER (R_NIOS_LO16_HI11, 3)
  RELOC_NUMBER (R_NIOS_HI16_LO5, 4)
  RELOC_NUMBER (R_NIOS_HI16_HI11, 5)
  RELOC_NUMBER (R_NIOS_PCREL6, 6)
  RELOC_NUMBER (R_NIOS_PCREL8, 7)
  RELOC_NUMBER (R_NIOS_PCREL11, 8)
  RELOC_NUMBER (R_NIOS_16, 9)   
  RELOC_NUMBER (R_NIOS_H_LO5, 10)
  RELOC_NUMBER (R_NIOS_H_HI11,11)
  RELOC_NUMBER (R_NIOS_H_XLO5, 12)
  RELOC_NUMBER (R_NIOS_H_XHI11, 13)
  RELOC_NUMBER (R_NIOS_H_16, 14)
  RELOC_NUMBER (R_NIOS_H_32, 15)
  RELOC_NUMBER (R_NIOS_GNU_VTINHERIT, 200)
  RELOC_NUMBER (R_NIOS_GNU_VTENTRY, 201)
  EMPTY_RELOC  (R_NIOS_max)
END_RELOC_NUMBERS

#define EF_NIOS_CPU_16		0x00000001      /* nios16 */
#define EF_NIOS_CPU_32	        0x00000002      /* nios32 */
#define EF_NIOS_CPU_MASK	0x00000003	/* specific cpu bits */
#define EF_NIOS_ALL_FLAGS	(EF_NIOS_CPU_MASK)

#endif /* _ELF_NIOS_H */




