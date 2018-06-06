/* BFD support for the NIOS processor.
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
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

//#include "bfd.h"
#include "mybfd.h"
#include "sysdep.h"
//#include "libbfd.h"

static int
bfd_default_scan (info, string)
     const bfd_arch_info_type *info;
     const char *string;
{
        return 1;
}

static const bfd_arch_info_type *
bfd_default_compatible (a, b)
     const bfd_arch_info_type *a;
     const bfd_arch_info_type *b;
{
  if (a->arch != b->arch)
    return NULL;

  if (a->bits_per_word != b->bits_per_word)
    return NULL;

  if (a->mach > b->mach) {
    return a;
  } else {
    return b;
  }
}

static const bfd_arch_info_type arch_info_struct[] =
{
  {
    32,				/* bits per word */
    32,				/* bits per address */
    8,				/* bits per byte */
    bfd_arch_nios,		/* architecture */
    bfd_mach_nios32,	/* machine */
    "nios",			/* architecture name */
    "nios32", 		/* printable name */
    4,				/* section align power */
    false,			/* the default ? */
    bfd_default_compatible,	/* architecture comparison fn */
    bfd_default_scan,		/* string to architecture convert fn */
    NULL,                 	/* next in list */
  }
};

const bfd_arch_info_type bfd_nios_arch =
{
  16,				/* bits per word */
  16,				/* bits per address */
  8,				/* bits per byte */
  bfd_arch_nios,		/* architecture */
  bfd_mach_nios16,		/* machine */
  "nios",			/* architecture name */
  "nios16", 		/* printable name */
  4,				/* section align power */
  true,				/* the default ? */
  bfd_default_compatible,	/* architecture comparison fn */
  bfd_default_scan,		/* string to architecture convert fn */
  &arch_info_struct[0],		/* next in list */
};


