/* radare2 - LGPL - Copyright 2021 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int m32c_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len, RAnalOpMask mask) {
	if (!op) {
		return 1;
	}
	op->size = 4;

	return op->size;
}

RAnalPlugin r_anal_plugin_m32c = {
	.name = "m32c",
	.desc = "m32c analysis plugin",
	.license = "LGPL3",
	.arch = "m32c",
	.esil = false,
	.bits = 32,
	.op = &m32c_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m32c,
	.version = R2_VERSION
};
#endif
