/* radare - LGPL - Copyright 2015 - pancake */

#include <stdio.h>

extern const char *dlangDemangle(const char *str);
extern int rt_init ();
extern int rt_term ();

//#define STR1 "_D4core8demangle8Demangle66__T10doDemangleS47_D4core8demangle8Demangle16parseMangledNameMFZvZ10doDemangleMFZAa"
//#define STR2 "_D4core8demangle8Demangle16parseMangledNameMFZv"

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static char *d_demangle(const char *str) {
	static int hasd = 0;
	char *ret;
	if (!hasd) {
		rt_init ();
		hasd = 1;
	}
	ret = strdup (dlangDemangle(str));
	//rt_term ();
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_dlang = {
	.name = "dlang",
	.desc = "dlang demangler",
	.license = "LGPL3",
	.demangle = &d_demangle,
	.demangle_type = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dlang,
	.version = R2_VERSION
};
#endif
