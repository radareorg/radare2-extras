/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_arch arch = KS_ARCH_ARM;
	ks_mode mode = KS_MODE_ARM;
	switch (a->bits) {
	case 16:
		mode = KS_MODE_THUMB;
		break;
	case 64:
		arch = KS_ARCH_ARM64;
		mode = KS_MODE_LITTLE_ENDIAN;
		a->big_endian = false;
		break;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, arch, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_arm_ks = {
	.name = "arm.ks",
	.arch = "arm",
	.desc = "ARM keystone assembler",
	.license = "GPL",
	.bits = 16|32|64,
	.assemble = &assemble
};

#ifndef CORELIB
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arm_ks,
	.version = RZ_VERSION
};
#endif

#ifdef __cplusplus
}
#endif
