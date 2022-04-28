/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/mips.h>
#include "keystone.c"

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_mode mode;
	switch (a->config->bits) {
	case 16:
		mode = KS_MODE_MICRO; // micromips mode
		break;
	case 32:
		mode = KS_MODE_MIPS32;
		break;
	case 64:
		mode = KS_MODE_MIPS64;
		break;
	}
	if (a->config->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, KS_ARCH_MIPS, mode);
}

RAsmPlugin r_asm_plugin_mips_ks = {
	.name = "mips.ks",
	.desc = "MIPS keystone assembler",
	.license = "GPL",
	.arch = "mips",
	.bits = 16|32|64,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_ks,
	.version = R2_VERSION
};
#endif
