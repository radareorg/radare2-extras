/* radare2 - GPL3 - Copyright 2021 - pancake */

#include <stdbool.h>
#include <r_lib.h>
#include <r_asm.h>
#include "gpu/disasm/disasm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char out[128];
	FILE *fp = fmemopen (out, sizeof (out), "w");
	*out = 0;
	bool stop = false;
	int res = agx_disassemble_instr ((uint8_t*)buf, &stop, false, fp);
	fclose (fp);
	
	r_strbuf_set (&op->buf_asm, out);
	op->size = res;

	return op->size;
}

RAsmPlugin r_asm_plugin_asahi = {
	.name = "asahi",
	.arch = "asahi",
	.bits = 32,
	.license = "MIT",
	.desc = "Asahi: Apple's M1 GPU",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_asahi,
	.version = R2_VERSION
};
#endif

