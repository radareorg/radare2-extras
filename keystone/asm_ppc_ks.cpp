/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/ppc.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	switch (a->bits) {
	case 32:
		mode = KS_MODE_PPC32;
		break;
	case 64:
		mode = KS_MODE_PPC64;
		break;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, KS_ARCH_PPC, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_ppc_ks = {
	.name = "ppc.ks",
	.arch = "ppc",
	.desc = "powerpc keystone assembler",
	.license = "GPL",
	.bits = 32|64,
	.assemble = &assemble,
};

#ifndef CORELIB
struct rz_lib_struct_t rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ppc_ks,
	.version = RZ_VERSION
};
#endif

#ifdef __cplusplus
}
#endif
