#ifndef __R2K_H
#define __R2K_H

#include <linux/version.h>
#include <linux/uaccess.h>

#if defined (CONFIG_X86_32) || defined(CONFIG_X86_64)
#include <asm/processor-flags.h>
#endif

#define R2_TYPE 0x69

/* Memory Part */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define get_user_pages          get_user_pages_remote
#define page_cache_release      put_page
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
#   define r2kmap_atomic(addr)		kmap_atomic(addr, KM_USER0)
#   define r2kunmap_atomic(addr)	kunmap_atomic(addr, KM_USER0)
#else
#   define r2kmap_atomic(addr)		kmap_atomic(addr)
#   define r2kunmap_atomic(addr)	kunmap_atomic(addr)
#endif

#define ADDR_OFFSET(x)          (x & (~PAGE_MASK))

#define IOCTL_READ_KERNEL_MEMORY        0x1
#define IOCTL_WRITE_KERNEL_MEMORY       0x2
#define IOCTL_READ_PROCESS_ADDR         0x3
#define IOCTL_WRITE_PROCESS_ADDR        0x4
#define IOCTL_READ_PHYSICAL_ADDR        0x5
#define IOCTL_WRITE_PHYSICAL_ADDR       0x6
#define IOCTL_GET_KERNEL_MAP            0x7

struct r2k_memory_transf {
        int pid;
        unsigned long addr;
        unsigned long len;
        void __user *buff;
        bool wp;
};

#define MAX_PHYS_ADDR	128

struct kernel_map_info {
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long phys_addr[MAX_PHYS_ADDR];
	int n_pages;
	int n_phys_addr;
};

struct kernel_maps {
	int n_entries;
	int size;
};

struct r2k_map {
	struct kernel_maps kernel_maps_info;
	struct kernel_map_info *map_info;
};

extern int addr_is_writeable (unsigned long addr);
extern int addr_is_mapped (unsigned long addr);
extern int dump_pagetables (void);
extern int pg_dump (struct r2k_map *k_map);

/**********************/

/* CPU-Registers Part */

#define IOCTL_READ_REG	0x8
#define IOCTL_PROC_INFO	0x9

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
#include "arch/x86/x86_definitions.h"
#else
#include "arch/arm/arm_definitions.h"
#endif

#if defined(CONFIG_X86_32) || defined(CONFIG_ARM)
#define reg_size 4
#elif defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
#define reg_size 8
#endif


struct r2k_control_reg {
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
	unsigned long cr0;
	unsigned long cr1;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
#ifdef CONFIG_X86_64
	unsigned long cr8;
#endif
#elif defined (CONFIG_ARM)
	unsigned long ttbr0;
	unsigned long ttbr1;
	unsigned long ttbcr;
	unsigned long c1;
	unsigned long c3;
#else
	unsigned long sctlr_el1;
	unsigned long ttbr0_el1;
	unsigned long ttbr1_el1;
	unsigned long tcr_el1;
#endif
};


//fails for kernel 3.15 x86
struct r2k_proc_info {
        pid_t pid;
        char comm[16]; //TASK_COMM_LEN = 16 include/linux/sched.h
        unsigned long vmareastruct[4096];
        unsigned long stack;
        unsigned long task;
};

/**********************/



/* Disable write protect */
static inline void disable_wp(void)
{
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
    preempt_disable();
    cr0_clear_bits(X86_CR0_WP);
#endif
}


static inline void enable_wp(void)
{
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
    cr0_set_bits(X86_CR0_WP);
    preempt_enable();
#endif
}


/* Workaround for HARDENED_USERCOPY */
#ifdef CONFIG_HARDENED_USERCOPY

static inline int
r2k_copy_from_user(void *dst, const void __user *src, unsigned size, bool wp)
{
	if (!wp) {
		disable_wp();
	}
	// memcpy (dst, src, size);
	copy_from_user (dst, src, size);
	if (!wp) {
		enable_wp();
	}
	return 0;
}

static inline int
r2k_copy_to_user(__user void *dst, const void *src, unsigned size)
{
	uint8_t *p = vmalloc (size);
	// intermediate copy to avoid kernel protection mechanisms to get triggered
	if (p) {
		memcpy (p, src, size);
		copy_to_user (dst, p, size);
		vfree (p);
	}
	return 0;
}

#else

static inline int
r2k_copy_from_user(void *dst, const void __user *src, unsigned size, bool wp)
{
    int res;

    if (!wp) disable_wp();
	res = copy_from_user(dst, src, size);
	// res = memcpy (dst, src, size);
    if (!wp) enable_wp();

    return res;
}

static inline int
r2k_copy_to_user(__user void *dst, const void *src, unsigned size)
{
	return copy_to_user(dst, src, size);
}

#endif /* CONFIG_HARDENED_USERCOPY */

#endif
