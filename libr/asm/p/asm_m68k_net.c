/* radare - GPL3 - Copyright 2009-2015 - nibble */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "m68k/m68k_disasm/m68k_disasm.h"

static int disassemble(RAsm *a, RAsmOp *aop, const ut8 *buf, int len) {
	m68k_word bof[8] = {0};
	int iaddr = (int)a->pc;
	char opcode[256], operands[256];
	const unsigned char *buf2;
	int ilen ;
	static struct DisasmPara_68k dp;
	char *buf_asm;
	/* initialize DisasmPara */
	*operands = *opcode = 0;
	memcpy (bof, buf, R_MIN(len, sizeof(bof)));
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = (m68k_word *) (size_t)iaddr;
	dp.instr = bof;
	buf2 = (const ut8*)M68k_Disassemble (&dp);
	if (!buf2) {
		// invalid instruction
		return aop->size = 2;
	}
	ilen = buf2 - (const ut8*)bof;
	if (*operands) {
		buf_asm = sdb_fmt ("%s %s", opcode, operands);
	} else {
		buf_asm = sdb_fmt ("%s", opcode);
	}
	r_str_replace_ch (buf_asm, '#', 0, 1);
	r_asm_op_set_asm (aop, buf_asm);
	aop->size = ilen;
	return aop->size;
}

RAsmPlugin r_asm_plugin_m68k = {
	.name = "m68k.net",
	.arch = "m68k",
	.license = "BSD",
	.bits = 16|32,
	.endian = R_SYS_ENDIAN_BIG,
	.desc = "Motorola 68000",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k,
	.version = R2_VERSION
};
#endif
