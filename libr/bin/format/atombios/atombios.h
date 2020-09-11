#ifndef _ATOMBIOS_H_
#define _ATOMBIOS_H_

#include <r_types.h>
#include <r_util.h>

// The atombios object for RBinFile
typedef struct atombios_obj_s {
        //atombios_hdr_t *header;
        RBuffer *b;
} atombios_obj_t;

#endif
