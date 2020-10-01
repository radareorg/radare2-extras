/* radare - LGPL - Copyright 2018 - damo22 */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/atombios/atombios.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char res[1024];
	res[0] = 0;
	op->size = atombios_disassemble (buf, len, res);
	r_strbuf_set (&op->buf_asm, res);
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return 0; // n
}

RAsmPlugin r_asm_plugin_atombios = {
	.name = "atombios",
	.author = "damo22",
	.version = "0.0.1",
	.arch = "atombios",
	.license = "LGPL3",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "AtomBIOS",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_atombios,
	.version = R2_VERSION
};
#endif
