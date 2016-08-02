/* radare2 - GPL3 - Copyright 2016 - ibabushkin */

#include <stdbool.h>
#include <r_lib.h>
#include <r_asm.h>
#include "asm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    // default values
    op->buf_asm[0] = 0;
    op->size = 2;

    agc_insn_t insn = {0};
    disasm_agc_insn (&insn, a->pc, ((const ut16 *)buf)[0], false);

    // we sometimes pass more arguments than the format string takes, but who
    // cares?
    snprintf (op->buf_asm, R_ASM_BUFSIZE, agc_mnemonics[insn.type], insn.operand);

    return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	// TODO
	return 0;
}

RAsmPlugin r_asm_plugin_agc = {
	.name = "agc",
	.arch = "agc",
	.bits = 16,
	.license = "GPL3",
	.desc = "AGC (Apollo Guidance Computer) disassembly plugin",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_agc,
	.version = R2_VERSION
};
#endif
