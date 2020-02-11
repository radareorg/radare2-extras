/* radare - LGPL - Copyright 2012-2020 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/z80_nc/disasm.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char str[128];
	int dlen = z80dis (0, buf, str, len);
	r_strbuf_set (&op->buf_asm, str);
	if (dlen<0) dlen = 0;
	op->size = dlen;
	return op->size;
}

RAsmPlugin r_asm_plugin_z80 = {
	.name = "z80.nc",
	.desc = "Zilog Z80 non-commerical",
	.license = "NC-GPL2", //NON-COMMERCIAL",
	.arch = "z80",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80,
	.version = R2_VERSION
};
#endif
