/* Minimal safe-ctype.h for the vc4 cgen sources, avoids depending on
   libiberty's _sch_istable.  */

#ifndef SAFE_CTYPE_H
#define SAFE_CTYPE_H

#include <ctype.h>

#define ISALNUM(c) isalnum ((unsigned char) (c))
#define ISALPHA(c) isalpha ((unsigned char) (c))
#define ISDIGIT(c) isdigit ((unsigned char) (c))
#define ISSPACE(c) isspace ((unsigned char) (c))
#define TOLOWER(c) tolower ((unsigned char) (c))
#define TOUPPER(c) toupper ((unsigned char) (c))

#endif
