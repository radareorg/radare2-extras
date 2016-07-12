/* radare - LGPL3 - Copyright 2016 - xarkes */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "../arch/swf/swfdis.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	RBinObject *obj = NULL;
	RBin *bin = a->binb.bin;

	obj = bin->cur->o;

	int dlen = r_asm_swf_disass (obj, op->buf_asm, buf, len, a->pc);
	op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_swf = {
	.name = "swf",
	.arch = "swf",
	.license = "LGPL3",
	.bits = 32,
	.desc = "SWF",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_swf,
	.version = R2_VERSION
};
#endif
