/* radare2-keystone - GPL - Copyright 2016-2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include "keystone.c"

static bool assemble(RArchSession *a, RAnalOp *ao, RArchEncodeMask mask) {
	ks_arch arch = KS_ARCH_ARM;
	ks_mode mode = KS_MODE_ARM;
	switch (a->config->bits) {
	case 16:
		mode = KS_MODE_THUMB;
		break;
	case 64:
		arch = KS_ARCH_ARM64;
		mode = KS_MODE_LITTLE_ENDIAN;
		a->config->big_endian = false;
		break;
	}
	if (a->config->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, ao->mnemonic, arch, mode);
}

RArchPlugin r_arch_plugin_arm_ks = {
	.meta = {
		.name = "arm.ks",
		.desc = "ARM keystone assembler",
		.license = "GPL",
	},
	.arch = "arm",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.encode = &assemble,
	.decode = NULL,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_arm_ks,
	.version = R2_VERSION
};
#endif
