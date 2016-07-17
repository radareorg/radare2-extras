#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_anal.h>

static int agc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
    // TODO: get rid of this, we have that in our disassembler already
    static bool extra_opcode_bit = false;
    if (!data || len != 2) return -1;
    op->size = 2;
    op->type = R_ANAL_OP_TYPE_UNK;

    if (!extra_opcode_bit) {

    } else {

    }
    return op->size;
}

RAnalPlugin r_anal_plugin_agc = {
	.name = "agc",
	.desc = "AGC code analysis plugin",
	.license = "LGPL3",
	.arch = "agc",
	.bits = 16,
	.op = &agc_op,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_agc,
	.version = R2_VERSION
};
#endif
