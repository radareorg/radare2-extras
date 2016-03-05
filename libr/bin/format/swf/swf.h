#ifndef SWF_H_
#define SWF_H_

#include <r_util.h>
#include <r_types.h>
#include <r_bin.h>
#include "swf_specs.h"

typedef struct __attribute__((__packed__)) {
	ut8 signature[3];
	ut8 version;
	ut32 file_size;
	ut8 rect_size;
	ut16 frame_rate;
	ut16 frame_count;
} swf_hdr;

char* get_swf_file_type(char compression, char flashVersion);
swf_hdr r_bin_swf_get_header(RBinFile *arch);
int r_bin_swf_get_sections(RList* list, RBinFile *arch);

#endif
