#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include "arm_definitions.h"
#include "dump_pagetables.h"

/*	
	Most of the code it has been taken from arch/-/mm/dump.c
	Here has just been added additional code to:
		- Supply phys addresses
		- Store info into r2k structure 
*/

static unsigned long start_vmalloc_allocated = 0;
static unsigned long end_vmalloc_allocated = 0;

static int entry = 0;
static int n_entries = 0;
static int ro;

static int addr_from_kernel(unsigned long addr)
{
	return addr == PAGE_OFFSET;
}

static int addr_from_vmalloc(unsigned long addr)
{
	return (addr == VMALLOC_START || addr == MODULES_VADDR);
}

static int addr_from_fixmap(unsigned long addr)
{
	return addr == FIXADDR_START;
}

static int addr_vmalloc_fixmap (unsigned long addr)
{
	return (addr_from_vmalloc (addr) ||
		addr_from_fixmap (addr));
}

static int addr_in_valid_range(unsigned long addr)
{
	return (addr_from_vmalloc (addr) ||
//		addr_from_fixmap (addr)	||
		addr_from_kernel (addr));
}
	
static void note_page(struct pg_state *st, unsigned long addr, unsigned level, u64 val)
{
        u64 prot = val & pg_level[level].mask;

	if (st->start_address >= start_vmalloc_allocated &&
		st->start_address <= start_vmalloc_allocated) {
		goto skip_process;
	}
	
        if (!st->level && !ro) {
                st->level = level;
                st->current_prot = prot;
        } else if (prot != st->current_prot || level != st->level ||
                   addr >= st->marker[1].start_address) {
                if (st->current_prot &&
			addr_in_valid_range (st->marker->start_address)) {
			if(ro) {
				n_entries++;
				goto skip_process;
			}

			if (entry < n_entries) {
				int nr_pages = (addr - st->start_address) / PAGE_SIZE;
				struct kernel_map_info *info = &st->k_map->map_info[entry];

				info->start_addr = st->start_address;
				info->end_addr = addr;

				if (nr_pages >= MAX_PHYS_ADDR)
					nr_pages = MAX_PHYS_ADDR - 1;
				info->n_pages = nr_pages;

				if (addr_from_kernel (st->marker->start_address)) {
					info->phys_addr[0] = __pa (st->start_address);
					info->phys_addr[1] = __pa (addr);
					info->n_phys_addr = 2;
					entry++;
				} else if (addr_from_vmalloc (st->marker->start_address) &&				
						level == 4) {
					int i;
					unsigned long aux_addr;
					for (i = 0, aux_addr = st->start_address; i < nr_pages; i++, aux_addr += PAGE_SIZE) {
						unsigned long pfn = vmalloc_to_pfn ((void *) aux_addr);
						if (!pfn_valid (pfn))
								info->phys_addr[i] = 0;
							else
								info->phys_addr[i] = (pfn << PAGE_SHIFT);
					}
					info->n_phys_addr = info->n_pages;
					entry++;
				}
			}
		}
						
skip_process:
                if (addr >= st->marker[1].start_address) {
                        st->marker++;
                }
                st->start_address = addr;
                st->current_prot = prot;
                st->level = level;
        }

#ifdef CONFIG_ARM64
	if (addr >= st->marker[1].start_address) {
		st->marker++;
	}
#endif
}

static void walk_pte(struct pg_state *st, pmd_t *pmd, unsigned long start)
{
        pte_t *pte = pte_offset_kernel(pmd, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
                addr = start + i * PAGE_SIZE;
		note_page(st, addr, 4, pte_val(*pte));
        }
}

static void walk_pmd(struct pg_state *st, pud_t *pud, unsigned long start)
{
        pmd_t *pmd = pmd_offset(pud, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
                addr = start + i * PMD_SIZE;
#ifdef CONFIG_ARM64
		if (pmd_none(*pmd) || pmd_sect (*pmd)) {
#else
		if (pmd_none(*pmd) || pmd_large(*pmd) || !pmd_present(*pmd)) {
#endif
                        note_page(st, addr, 3, pmd_val(*pmd));
                } else {
                        walk_pte(st, pmd, addr);
		}
#ifdef CONFIG_ARM
                if (SECTION_SIZE < PMD_SIZE && pmd_large(pmd[1])) 
                        note_page(st, addr + SECTION_SIZE, 3, pmd_val(pmd[1]));
#endif
        }
}

static void walk_pud(struct pg_state *st, pgd_t *pgd, unsigned long start)
{
        pud_t *pud = pud_offset(pgd, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
                addr = start + i * PUD_SIZE;
#if defined CONFIG_ARM64 && !defined (CONFIG_ANDROID)
		if (pud_none (*pud) || pud_sect (*pud)) {
			note_page (st, addr, 2, pud_val (*pud));
		} else {
		       	walk_pmd (st, pud, addr);
		}
#else
                if (!pud_none(*pud)) {
			walk_pmd (st, pud, addr);
		} else {
			note_page (st, addr, 2, pud_val (*pud));
		}
#endif
        }
}

static void walk_pgd(struct r2k_map *k_map)
{
        pgd_t *pgd;
        struct pg_state st;
        unsigned long addr;
        unsigned i;

        memset(&st, 0, sizeof(st));
        st.marker = address_markers;
	st.k_map = k_map;

	pgd = get_global_pgd ();

        for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
#ifdef CONFIG_ARM64
                addr = VA_START + i * PGDIR_SIZE;
#else
		addr = i * PGDIR_SIZE;
#endif
                if (!pgd_none(*pgd)) {
                        walk_pud(&st, pgd, addr);
                } else {
			note_page(&st, addr, 1, pgd_val(*pgd));
                }
        }

	if (!ro)
	        note_page(&st, 0, 0, 0);
}

int pg_dump(struct r2k_map *k_map)
{
        unsigned i, j;
	int size;
	unsigned long addr;

        for (i = 0; i < ARRAY_SIZE(pg_level); i++)
               	if (pg_level[i].bits)
                       	for (j = 0; j < pg_level[i].num; j++)
                               	pg_level[i].mask |= pg_level[i].bits[j].mask;

#ifdef CONFIG_ARM
        address_markers[2].start_address = VMALLOC_START;
#endif
	ro = 1;
	walk_pgd (k_map);

	size = n_entries * sizeof (struct kernel_map_info);
	
	k_map->map_info = vmalloc (size);
	if (!k_map->map_info) {
		pr_info ("vmalloc error\n");
		return -ENOMEM;
	}

	size = PAGE_ALIGN (size);
	start_vmalloc_allocated = (unsigned long)k_map->map_info;
	end_vmalloc_allocated = start_vmalloc_allocated + size + PAGE_SIZE;

	addr = start_vmalloc_allocated;
	for (addr = start_vmalloc_allocated ; 
		addr < end_vmalloc_allocated - PAGE_SIZE; addr += PAGE_SIZE) 
		SetPageReserved (vmalloc_to_page ((void*)addr));
	
	ro = 0;
	walk_pgd (k_map);

	k_map->kernel_maps_info.size = size;
	k_map->kernel_maps_info.n_entries = entry;

	start_vmalloc_allocated = end_vmalloc_allocated = n_entries = entry = 0;
	return 0;
}

