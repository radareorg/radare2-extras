/* radare - LGPL - Copyright 2010-2018 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/arm/arm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int *p = (int*)buf; // TODO : endian
	char buf_asm[64] = {0};
	op->size = armthumb_disassemble (buf_asm, (ut32)a->pc, *p);
	if (op->size > 0) {
		r_strbuf_set (&op->buf_asm, buf_asm);
	} else {
		r_strbuf_set (&op->buf_asm, " (data)");
	}
	return op->size;
}

#if 0
static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int opcode = armass_assemble (buf, a->pc, true);
	if (opcode==-1)
		return -1;
	r_mem_copyendian (op->buf, (void *)&opcode, 2, a->big_endian);
	return armthumb_length (opcode);
}
#endif

RAsmPlugin r_asm_plugin_armthumb = {
	.name = "arm.thumb",
	.arch = "arm",
	.bits = 16,
	.desc = "ARM THUMB disassembly plugin",
	.disassemble = &disassemble,
//	.assemble = &assemble 
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_armthumb,
	.version = R2_VERSION
};
#endif
