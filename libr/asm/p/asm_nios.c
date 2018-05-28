/* nios plugin by hewittc at 2018 */

#include <r_asm.h>
#include <r_lib.h>

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return 1;
}

RAsmPlugin r_asm_plugin_nios = {
	.name = "nios",
	.arch = "nios",
	.license = "GPL3",
	.bits = 16,
	.desc = "Nios disassembler",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_nios
};
#endif
