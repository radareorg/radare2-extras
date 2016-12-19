#ifndef __ARM_DEFINITIONS_H
#define __ARM_DEFINITIONS_H

#ifdef CONFIG_ARM64
#include "arm64_definitions.h"
#elif defined CONFIG_ARM_LPAE
#include "arm_lpae_definitions.h"
#else
#include "arm32_definitions.h"
#endif

#ifndef pmd_large
# define pmd_large(x)   (pmd_val(x) & 2)
#endif

#if !defined (pmd_write) && !defined (CONFIG_DEBUG_RODATA)
#  define pmd_write(x)          (1)
#endif

#define PAGE_IS_RW(x)           pte_write(x)
#define PAGE_IS_PRESENT(x)      pte_present(x)

#define WRITE_TYPE              0x1
#define PRESENT_TYPE            0x2

#endif	

