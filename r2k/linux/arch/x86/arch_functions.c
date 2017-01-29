#include <linux/mm.h>
#include "x86_definitions.h"

# define PAGE_IS_PRESENT(x)     (pte_val (x) & _PAGE_PRESENT)
# define PAGE_IS_READONLY(x)    (pte_val (x) & _PAGE_RW)

static pte_t *virt_to_pte (unsigned long addr)
{
	unsigned int level;
	return lookup_address (addr, &level);
}

int addr_is_mapped (unsigned long addr)
{
	pte_t *pte;

	pte = virt_to_pte (addr);
	if (pte)
		return PAGE_IS_PRESENT (*pte);
	return 0;
}

int addr_is_writeable (unsigned long addr)
{
	pte_t *pte;

	pte = virt_to_pte (addr);
	if (pte)
		return PAGE_IS_READONLY (*pte);
	return 0;
}

