/* radare2-keystone - GPL - Copyright 2016-2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/ppc.h>
#include "keystone.c"

static bool assemble(RArchSession *a, RAnalOp *ao, RArchEncodeMask mask) {
	ks_mode mode = (ks_mode)0;
	switch (a->config->bits) {
	case 32:
		mode = KS_MODE_PPC32;
		break;
	case 64:
		mode = KS_MODE_PPC64;
		break;
	}
	if (a->config->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, ao->mnemonic, KS_ARCH_PPC, mode);
}

RArchPlugin r_arch_plugin_ppc_ks = {
	.meta = {
		.name = "ppc.ks",
		.desc = "powerpc keystone assembler",
		.license = "GPL",
	},
	.arch = "ppc",
	.bits = R_SYS_BITS_PACK2 (32,64),
	.encode = &assemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ppc_ks,
	.version = R2_VERSION
};
#endif
