/* radare2 - GPL3 - Copyright 2021-2023 - pancake */

#include <r_lib.h>
#include <r_arch.h>
#include "gpu/disasm/disasm.c"

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	char out[128];
	FILE *fp = fmemopen (out, sizeof (out), "w");
	*out = 0;
	bool stop = false;
	int res = agx_disassemble_instr ((uint8_t*)op->bytes, &stop, false, fp);
	fclose (fp);
	r_str_replace_char (out, '\n', ' ');
	free (op->mnemonic);
	op->mnemonic = r_str_trim_dup (out);
	op->size = res;

	return op->size;
}

static RArchPlugin r_arch_plugin_asahi = {
	.meta = {
		.name = "asahi",
		.license = "MIT",
		.desc = "Asahi: Apple's M1 GPU",
	},
	.arch = "asahi",
	.bits = 32,
	.decode = &decode,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_asahi,
	.version = R2_VERSION
};
#endif

