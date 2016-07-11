#include <r_lib.h>
#include <r_asm.h>
// #include "../arch/agc/agc.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	// TODO
	return 0;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	// TODO
	return 0;
}

RAsmPlugin r_asm_plugin_agc = {
	.name = "agc",
	.arch = "agc",
	.bits = 16,
	.desc = "AGC (Apollo Guidance Computer) disassembly plugin",
	.init = NULL,
	.fini = NULL,
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
