#ifndef __ARM64_DEFINITIONS_H
#define __ARM64_DEFINITIONS_H

#define read_ttbr0_EL1()				\
	({						\
		unsigned long __dummy;			\
		__asm__ ("mrs	%0, TTBR0_EL1"		\
			: "=r" (__dummy));		\
		__dummy;				\
	})

#define read_ttbr1_EL1()				\
	({						\
		unsigned long __dummy;			\
		__asm__ ("mrs     %0, TTBR1_EL1"	\
			: "=r" (__dummy));		\
		__dummy;				\
	})	

#define read_tcr_EL1() 					\
	({						\
		unsigned long __dummy;			\
		__asm__ ("mrs	%0, TCR_EL1"		\
			: "=r" (__dummy));		\
		__dummy;				\
	})

#define read_sctlr_EL1()                                \
        ({                                              \
		unsigned long __dummy;                  \
		__asm__ ("mrs %0, SCTLR_EL1"         	\
			: "=r" (__dummy));              \
		__dummy;                                \
        })	

static pgd_t *get_global_pgd (void)
{
	unsigned long ttb_reg;

	ttb_reg = read_ttbr1_EL1 ();
	ttb_reg &= (0xffffffffffffffff << 0x9);

	return __va (ttb_reg);
}
#endif
