/* radare2 - BSD - Copyright 2016 - ibabushkin */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_anal.h>
#include "anal.h"

static int agc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	// early exit on illegal inputs
	if (!data || len != 2) {
		return -1;
	}
	analyze_agc_insn (op, addr, ((const ut16 *)data)[0], false);
	return op->size;
}

RAnalPlugin r_anal_plugin_agc = {
	.name = "agc",
	.arch = "agc",
	.bits = 16,
	.license = "BSD",
	.desc = "AGC (Apollo Guidance Computer) code analysis plugin",
	.op = &agc_op,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_agc,
	.version = R2_VERSION
};
#endif
