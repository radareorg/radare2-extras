/* radare - GPL3 - Copyright 2009-2015 - pancake, nibble */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "x86/bea/BeaEngine.h"
//#include "fastcall_x86.h"

static int disassemble(RAsm *a, RAsmOp *aop, const ut8 *buf, int len) {
	static DISASM disasm_obj;

	memset (&disasm_obj, '\0', sizeof (DISASM));
	disasm_obj.EIP = (long long)buf;
	disasm_obj.VirtualAddr = a->pc;
	disasm_obj.Archi = ((a->bits == 64) ? 64 : 0);
	disasm_obj.SecurityBlock = len;
	if (a->syntax == R_ASM_SYNTAX_ATT)
		disasm_obj.Options = 0x400;
	else disasm_obj.Options = 0;

	aop->size = Disasm (&disasm_obj);
	r_asm_op_set_asm (aop, disasm_obj.CompleteInstr);

	return aop->size;
}

static RAsmPlugin r_asm_plugin_x86_bea = {
	.name = "x86.bea",
	.desc = "x86 BeaEngine disassembler plugin",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.disassemble = &disassemble,
	.license = "LGPL"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_bea,
	.version = R2_VERSION
};
#endif
