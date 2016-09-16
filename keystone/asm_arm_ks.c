/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include "keystone.c"

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_arch arch = KS_ARCH_ARM;
	ks_mode mode;
	mode = KS_MODE_ARM;
	switch (a->bits) {
	case 16:
		mode = KS_MODE_THUMB;
		break;
	case 64:
		arch = KS_ARCH_ARM64;
		mode = KS_MODE_LITTLE_ENDIAN;
		break;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, arch, mode);
}

RAsmPlugin r_asm_plugin_arm_ks = {
	.name = "arm.ks",
	.desc = "ARM keystone assembler",
	.license = "GPL",
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
