/* radare - LGPL3 - Copyright 2016 - xarkes */

#include "swfdis.h"
#include "swf_op.h"

swf_op_t r_asm_swf_getop(ut8 opCode) {
	int i;
	for (i = 0; swf_op[i].name != NULL; i++) {
		if (opCode == swf_op[i].op) {
			return swf_op[i];
		}
	}
	return SWF_OP_UNKNOWN;
}

swf_tag_t r_asm_swf_gettag(ut16 tagCode) {
	int i;
	for (i = 0; swf_tag[i].name != NULL; i++) {
		if (tagCode == swf_tag[i].tag) {
			return swf_tag[i];
		}
	}
	return SWF_TAG_UNKNOWN;
}

int r_asm_swf_disass(RBinObject *obj, char* buf_asm, const ut8* buf, int len, ut64 pc) {
	ut8 isTag = false;
	int dlen;
	RListIter *it;
	RBinSection *sect;

	r_list_foreach(obj->sections, it, sect) {
		if (pc == sect->vaddr) {
			isTag = true;
			break;
		}
	}

	if (isTag && len > 1) {
		dlen = 2;
		ut16 tagCodeAndLength = 0;
		ut16 tagCode = 0;
		ut32 tagLength;
		tagCodeAndLength = buf[0] + (buf[1] << 8);

		tagCode = tagCodeAndLength >> 6;
		tagLength = tagCodeAndLength & 0x3f;

		if (tagLength >= 0x3f) {
			dlen = 6;
			//r_buf_read_at (buf, 2, (ut8*)&tagLength, 4);
		}
		swf_tag_t tag = r_asm_swf_gettag (tagCode);

		switch (tagCode) {
		case TAG_SETBACKGROUNDCOLOR:
			strcpy (buf_asm, tag.name);
			break;
		default:
			strcpy (buf_asm, tag.name);
			break;

		}

	} else {
		swf_op_t op = r_asm_swf_getop (buf[0]);
		switch (op.op) {
		default:
			sprintf (buf_asm, "%s", op.name); //TODO strcpy
			dlen = 1;

		}
	}

	return dlen;
}
