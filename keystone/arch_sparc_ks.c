/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/sparc.h>

#include "keystone.c"
static bool assemble(RArchSession *a, RAnalOp *ao, RArchEncodeMask mask) {
	ks_mode mode = (ks_mode)0;
	switch (a->config->bits) {
	case 32:
		mode = KS_MODE_SPARC32;
		break;
	case 64:
		mode = KS_MODE_SPARC64;
		break;
	}
	if (a->config->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, ao->mnemonic, KS_ARCH_SPARC, mode);
}

RArchPlugin r_arch_plugin_sparc_ks = {
	.name = "sparc.ks",
	.desc = "sparc keystone assembler",
	.license = "GPL",
	.arch = "sparc",
	.bits = R_SYS_BITS_PACK2 (32,64),
	.encode = &assemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_sparc_ks,
	.version = R2_VERSION
};
#endif
