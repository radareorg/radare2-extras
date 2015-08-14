#include <assert.h>
#include <stdio.h>

#define CORE_ADDR unsigned long long
#define PTR void*
#define RETURN_QUIT -2
#define CHECK_FATAL assert
#define RETURN_MASK_ALL 0xffffff
#define STREQ !strcmp
#define eprintf(x,y...) fprintf(stderr,x,##y)
#define warning(x,y...) fprintf(stderr,x"\n",##y)
