#ifndef __ARM32_DEFINITIONS_H
#define __ARM32_DEFINITIONS_H

#define read_ttbr(n) 							\
		({							\
			unsigned long __dummy;				\
			__asm__ ("mrc	p15, 0, %0, c2, c0, "#n""	\
				: "=r" (__dummy));			\
			__dummy;					\
		})							\

#define read_ttbcr()							\
		({							\
			unsigned long __dummy;				\
			__asm__ ("mrc	p15, 0, %0, c2, c0, 2"		\
				: "=r" (__dummy));			\
			__dummy;					\
		})

#define read_c1()							\
		({							\
			unsigned long __dummy;				\
			__asm__ ("mrc   p15, 0, %0, c1, c0, 0"		\
				: "=r" (__dummy));			\
			__dummy;					\
		})

#define read_c3()							\
		({							\
			unsigned long __dummy;				\
			__asm__ ("mrc	p15, 0, %0, c3, c0, 0"		\
				: "=r" (__dummy));			\
			__dummy;					\
		})

static pgd_t *get_global_pgd (void)
{
	unsigned long ttb_reg;

	ttb_reg = read_ttbr (1);
	ttb_reg &= ~0x3fff;

	return __va (ttb_reg);
}
#endif	

