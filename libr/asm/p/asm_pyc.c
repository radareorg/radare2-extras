#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "pyc_dis.h"

static int disassemble (RAsm *a, RAsmOp *opstruct, const ut8 *buf, int len) {
	RList *interned_table = NULL;
	RList *shared = NULL;
	RList *cobjs = NULL;

	RBin *bin = a->binb.bin;
	ut64 pc = a->pc;
  
	RBinPlugin *plugin = bin && bin->cur && bin->cur->o ?
		bin->cur->o->plugin : NULL;

	if (plugin) {
		if (!strcmp (plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	cobjs = r_list_get_n (shared, 0);
	interned_table = r_list_get_n (shared, 1);
	int r = r_pyc_disasm (opstruct, buf, cobjs, interned_table, pc);
	opstruct->size = r;
	return r;
}

static bool init (void *user) {
	init_opname_table ();
	return true;
}

RAsmPlugin r_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 32,
	.desc = "PYC disassemble plugin",
	.disassemble = &disassemble,
	.init = &init,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pyc,
	.version = R2_VERSION
};

#endif
