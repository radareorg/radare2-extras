/* radare - LGPL - Copyright 2021 - pancake */
#if 0
gcc -o core_test.so -fPIC `pkg-config --cflags --libs r_core` core_test.c -shared
mkdir -p ~/.config/radare2/plugins
mv core_test.so ~/.config/radare2/plugins
#endif

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static int mycall(void *user, const char *input) {
	int i, j;
	const int seqsz = 100;
	int data[seqsz];
	RCore *core = (RCore *) user;
	if (!strncmp (input, "aetr", 4)) {
		unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
		int stacksize = r_config_get_i (core->config, "esil.stack.depth");
		bool iotrap = r_config_get_i (core->config, "esil.iotrap");
		bool romem = r_config_get_i (core->config, "esil.romem");
		bool stats = r_config_get_i (core->config, "esil.stats");
		// anal ESIL to REIL.
		RAnalEsil *esil = r_anal_esil_new (stacksize, iotrap, addrsize);
		if (!esil) {
			return 0;
		}
		r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
		r_anal_esil_set_pc (esil, core->offset);
		r_anal_esil_parse (esil, input + 2);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_free (esil);
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_esil2reil = {
	.name = "esil2reil",
	.author = "sushant",
	.desc = "convert ESIL expressions into REIL",
	.license = "BSD",
	.call = mycall,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_esil2reil,
	.version = R2_VERSION
};
#endif
