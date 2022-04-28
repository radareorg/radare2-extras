/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <keystone/keystone.h>
#include <keystone/systemz.h>
#include "keystone.c"

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	if (a->config->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, KS_ARCH_SYSTEMZ, mode);
}

RAsmPlugin r_asm_plugin_sysz_ks = {
	.name = "sysz.ks",
	.desc = "SystemZ keystone assembler (S390X)",
	.license = "GPL",
	.arch = "sysz",
	.bits = 32,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sysz_ks,
	.version = R2_VERSION
};
#endif
