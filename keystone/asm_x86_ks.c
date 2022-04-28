/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/x86.h>

#include "keystone.c"
static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	switch (a->config->bits) {
	case 16:
		mode = KS_MODE_16;
		break;
	case 32:
		mode = KS_MODE_32;
		break;
	case 64:
		mode = KS_MODE_64;
		break;
	}
	return keystone_assemble (a, ao, str, KS_ARCH_X86, mode);
}

RAsmPlugin r_asm_plugin_x86_ks = {
	.name = "x86.ks",
	.desc = "x86 keystone assembler",
	.license = "GPL",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_ks,
	.version = R2_VERSION
};
#endif
