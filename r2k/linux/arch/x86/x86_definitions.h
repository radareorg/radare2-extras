#ifndef __X86_DEFINITIONS__H__
#define __X86_DEFINITIONS__H__

#include <linux/version.h>

#if (defined(CONFIG_X86_32) || defined(CONFIG_X86_64))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0))
#include <asm/special_insns.h>
#elif (KERNEL_VERSION(3,4,0) > LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
#include <asm/system.h>
#elif (KERNEL_VERSION(2,6,28) > LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
#include <asm-x86/system.h>
#elif (KERNEL_VERSION(2,6,24) > LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#include <asm-i386/system.h>
#elif (KERNEL_VERSION(2,6,22) > LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))//KERNEL_VERSION(2,6,14)
#include <asm-i386/system.h>
#define native_read_cr0 read_cr0

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)) && defined (CONFIG_X86_32)
#define native_read_cr4_safe() ({		\
	unsigned long __dummy;			\
	__asm__("1:mov %%cr4, %0           \n"	\
		"2:                         \n"	\
		".section __ex_table,\"a\"  \n"	\
		".long 1b, 2b               \n"	\
		".previous                  \n"	\
		:"=r" (__dummy): "0" (0));	\
	__dummy;				\
})
#else
#define native_read_cr4_safe read_cr4
#endif	/* defined as it is in 2.6.16 */

#ifdef CONFIG_X86_64
#define native_read_cr8 read_cr8
#endif

#ifdef read_cr2
#define native_read_cr2 read_cr2
#else
#define native_read_cr2() ({				\
	unsigned long __dummy;				\
	__asm__ __volatile__(				\
			     "mov %%cr2, %0\n\t"	\
			     :"=r" (__dummy));		\
	__dummy;					\
})
#endif	/* defined as it is in 2.6.16 */

#ifdef read_cr3
#define native_read_cr3 read_cr3
#else
#define native_read_cr3() ({		\
	unsigned long __dummy;		\
	__asm__ (			\
		 "mov %%cr3, %0\n\t"	\
		 :"=r" (__dummy));	\
	__dummy;			\
})
#endif	/* defined as it is in 2.6.16 */
#endif

#endif


static inline void cr0_set_bits(unsigned long mask)
{
    unsigned long cr0;

    cr0 = native_read_cr0();
    if ((cr0 | mask) != cr0) {
        cr0 |= mask;
        asm volatile("mov %0,%%cr0": : "r" (cr0), "m" (__force_order));
	}
}

static inline void cr0_clear_bits(unsigned long mask)
{
    unsigned long cr0;

    cr0 = native_read_cr0();
    if ((cr0 & ~mask) != cr0) {
            cr0 &= ~mask;
            asm volatile("mov %0,%%cr0": : "r" (cr0), "m" (__force_order));
    }
}

#endif
