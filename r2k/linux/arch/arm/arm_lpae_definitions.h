#ifndef __ARM_LPAE_DEFINITIONS_H
#define __ARM_LPAE_DEFINITIONS_H

#define read_ttbr(n) 							\
		({							\
			u64 __dummy;					\
			__asm__ ("mrrc	p15, " #n ", %Q0, %R0, c2"	\
				: "=r" (__dummy));			\
			__dummy;					\
		})

#define read_ttbcr()							\
		({							\
			unsigned long __dummy;				\
			__asm__ ("mrc   p15, 0, %0, c2, c0, 0"		\
				: "=r" (__dummy));			\
			__dummy;					\
                })

static pgd_t *get_global_pgd (void)
{
	u64 ttb_reg;
	
	ttb_reg = read_ttbr (1);
		
	if (PAGE_OFFSET == 0x80000000)
		ttb_reg -= (1 << 4);
	else if (PAGE_OFFSET == 0xc0000000)
		ttb_reg -= (16 << 10);
	ttb_reg &= ~(PTRS_PER_PGD*sizeof(pgd_t)-1);
	
	return __va (ttb_reg);
}
#endif
