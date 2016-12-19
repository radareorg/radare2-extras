#ifndef __DUMP_PAGETABLES32_H
#define __DUMP_PAGETABLES32_H

#include "arm_definitions.h"

/*	
	Most of the code it has been taken from arch/-/mm/dump.c
	Here has just been added additional code to supply physical addresses 
*/
	
struct addr_marker {
        unsigned long start_address;
        const char *name;
};

static struct addr_marker address_markers[] = {
        { MODULES_VADDR,        "Modules" },
        { PAGE_OFFSET,          "Kernel Mapping" },
        { 0,                    "vmalloc() Area" },
        { VMALLOC_END,          "vmalloc() End" },
        { FIXADDR_START,        "Fixmap Area" },
        { CONFIG_VECTORS_BASE,  "Vectors" },
        { CONFIG_VECTORS_BASE + PAGE_SIZE * 2, "Vectors End" },
        { -1,                   NULL },
};

struct pg_state {
	struct r2k_map *k_map;
	int n_entries;
        const struct addr_marker *marker;
        unsigned long start_address;
        unsigned level;
        u64 current_prot;
};

struct prot_bits {
        u64             mask;
        u64             val;
        const char      *set;
        const char      *clear;
};

static const struct prot_bits pte_bits[] = {
        {
                .mask   = L_PTE_USER,
                .val    = L_PTE_USER,
                .set    = "USR",
                .clear  = "   ",
        }, {
                .mask   = L_PTE_RDONLY,
                .val    = L_PTE_RDONLY,
                .set    = "ro",
                .clear  = "RW",
        }, {
                .mask   = L_PTE_XN,
                .val    = L_PTE_XN,
                .set    = "NX",
                .clear  = "x ",
        }, {
                .mask   = L_PTE_SHARED,
                .val    = L_PTE_SHARED,
                .set    = "SHD",
                .clear  = "   ",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_UNCACHED,
                .set    = "SO/UNCACHED",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_BUFFERABLE,
                .set    = "MEM/BUFFERABLE/WC",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_WRITETHROUGH,
                .set    = "MEM/CACHED/WT",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_WRITEBACK,
                .set    = "MEM/CACHED/WBRA",
#ifndef CONFIG_ARM_LPAE
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_MINICACHE,
                .set    = "MEM/MINICACHE",
#endif
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_WRITEALLOC,
                .set    = "MEM/CACHED/WBWA",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_DEV_SHARED,
                .set    = "DEV/SHARED",
#ifndef CONFIG_ARM_LPAE
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_DEV_NONSHARED,
                .set    = "DEV/NONSHARED",
#endif
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_DEV_WC,
                .set    = "DEV/WC",
        }, {
                .mask   = L_PTE_MT_MASK,
                .val    = L_PTE_MT_DEV_CACHED,
                .set    = "DEV/CACHED",
        },
};

static const struct prot_bits section_bits[] = {
#ifdef CONFIG_ARM_LPAE
        {
                .mask   = PMD_SECT_USER,
                .val    = PMD_SECT_USER,
                .set    = "USR",
        }, {
                .mask   = L_PMD_SECT_RDONLY,
                .val    = L_PMD_SECT_RDONLY,
                .set    = "ro",
                .clear  = "RW",
#elif __LINUX_ARM_ARCH__ >= 6
        {
                .mask   = PMD_SECT_APX | PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_APX | PMD_SECT_AP_WRITE,
                .set    = "    ro",
        }, {
                .mask   = PMD_SECT_APX | PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_WRITE,
                .set    = "    RW",
        }, {
                .mask   = PMD_SECT_APX | PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_READ,
                .set    = "USR ro",
        }, {
		                .mask   = PMD_SECT_APX | PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .set    = "USR RW",
#else /* ARMv4/ARMv5  */
        /* These are approximate */
        {
                .mask   = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = 0,
                .set    = "    ro",
        }, {
                .mask   = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_WRITE,
                .set    = "    RW",
        }, {
                .mask   = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_READ,
                .set    = "USR ro",
        }, {
                .mask   = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .val    = PMD_SECT_AP_READ | PMD_SECT_AP_WRITE,
                .set    = "USR RW",
#endif
        }, {
                .mask   = PMD_SECT_XN,
                .val    = PMD_SECT_XN,
                .set    = "NX",
                .clear  = "x ",
        }, {
                .mask   = PMD_SECT_S,
                .val    = PMD_SECT_S,
                .set    = "SHD",
                .clear  = "   ",
        },
};

struct pg_level {
        const struct prot_bits *bits;
        size_t num;
        u64 mask;
};

static struct pg_level pg_level[] = {
        {
        }, { /* pgd */
        }, { /* pud */
        }, { /* pmd */
                .bits   = section_bits,
                .num    = ARRAY_SIZE(section_bits),
        }, { /* pte */
                .bits   = pte_bits,
                .num    = ARRAY_SIZE(pte_bits),
        },
};

#endif
