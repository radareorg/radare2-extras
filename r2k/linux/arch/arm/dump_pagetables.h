#ifndef __DUMP_PAGETABLES_H
#define __DUMP_PAGETABLES_H

#ifdef CONFIG_ARM64
#include  "dump_pagetables64.h"
#else
#include  "dump_pagetables32.h"
#endif

#include "../../r2k.h"

#ifndef pmd_sect
#define pmd_sect(pmd)		(pmd_val (pmd) & PROT_SECT_DEFAULT)
#endif

#endif
