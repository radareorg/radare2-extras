/* radare2-keystone - GPL - Copyright 2016-2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/mips.h>
#include "keystone.c"

static bool assemble(RArchSession *a, RAnalOp *ao, RArchEncodeMask mask) {
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
	return keystone_assemble (a, ao, ao->mnemonic, KS_ARCH_MIPS, mode);
}

RArchPlugin r_arch_plugin_mips_ks = {
	.meta = {
		.name = "mips.ks",
		.desc = "MIPS keystone assembler",
		.license = "GPL",
	},
	.arch = "mips",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.encode = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_mips_ks,
	.version = R2_VERSION
};
#endif
