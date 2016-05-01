/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include "keystone.c"

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_arch arch;
	ks_mode mode;
	switch (a->bits) {
	case 16:
		mode = KS_MODE_THUMB;
		break;
	case 32:
		mode = KS_MODE_32;
		break;
	case 64:
		mode = KS_MODE_64;
		break;
	}
	if (a->bits == 64) {
		arch = KS_ARCH_ARM64;
	} else {
		arch = KS_ARCH_ARM;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, arch, mode);
}

RAsmPlugin r_asm_plugin_arm_ks = {
	.name = "arm.ks",
	.desc = "ARM keystone assembler",
	.license = "BSD",
	.arch = "arm",
	.bits = 16|32|64,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_ks,
	.version = R2_VERSION
};
#endif
