/* radare2-keystone - GPL - Copyright 2016-2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/x86.h>
#include "keystone.c"

static bool assemble(RArchSession *a, RAnalOp *ao, RArchEncodeMask mask) {
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
	return keystone_assemble (a, ao, ao->mnemonic, KS_ARCH_X86, mode);
}

RArchPlugin r_arch_plugin_x86_ks = {
	.meta = {
		.name = "x86.ks",
		.desc = "x86 keystone assembler",
		.license = "GPL",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.encode = &assemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_x86_ks,
	.version = R2_VERSION
};
#endif
