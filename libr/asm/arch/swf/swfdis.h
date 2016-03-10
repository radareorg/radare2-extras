#include <r_bin.h>
#include <r_types.h>

typedef struct {
	ut8 op;
	const char* name;
} swf_op_t;

typedef struct {
	ut16 tag;
	const char* name;
} swf_tag_t;

swf_op_t r_asm_swf_getop(ut8 opCode);
swf_tag_t r_asm_swf_gettag(ut16 tagCode);
int r_asm_swf_disass(RBinObject *obj, char* buf_asm, const ut8* buf, int len, ut64 pc);
