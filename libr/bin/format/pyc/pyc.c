/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#include <r_util.h>
#include "pyc.h"

static char *get_python_version(enum pyc_magic magic) {
	switch (magic) {
	case MAGIC_1_0:
		return "1.0";
	case MAGIC_1_1:
		return "1.1";
	case MAGIC_1_3:
		return "1.3";
	case MAGIC_1_4:
		return "1.4";
	case MAGIC_1_5:
		return "1.5";
	case MAGIC_1_6:
		return "1.6";
	case MAGIC_2_0:
		return "2.0";
	case MAGIC_2_1:
		return "2.1";
	case MAGIC_2_2:
		return "2.2";
	case MAGIC_2_3a0_v0:
	case MAGIC_2_3a0_v1:
		return "2.3a0";
	case MAGIC_2_4a0:
		return "2.4a0";
	case MAGIC_2_4a3:
		return "2.4a3";
	case MAGIC_2_4b1:
		return "2.4b1";
	case MAGIC_2_5a0_v0:
	case MAGIC_2_5a0_v1:
	case MAGIC_2_5a0_v2:
	case MAGIC_2_5a0_v3:
		return "2.5a0";
	case MAGIC_2_5b3_v0:
	case MAGIC_2_5b3_v1:
		return "2.5b3";
	case MAGIC_2_5c1:
		return "2.5c1";
	case MAGIC_2_5c2:
		return "2.5c2";
	case MAGIC_2_6a0:
		return "2.6a0";
	case MAGIC_2_6a1:
		return "2.6a1";
	case MAGIC_2_7a0_v0:
	case MAGIC_2_7a0_v1:
	case MAGIC_2_7a0_v2:
	case MAGIC_2_7a0_v3:
	case MAGIC_2_7a0_v4:
		return "2.7a0";
	case MAGIC_3000_v0:
	case MAGIC_3000_v1:
	case MAGIC_3000_v2:
	case MAGIC_3000_v3:
	case MAGIC_3000_v4:
	case MAGIC_3000_v5:
	case MAGIC_3000_v6:
	case MAGIC_3000_v7:
	case MAGIC_3000_v8:
	case MAGIC_3000_v9:
	case MAGIC_3000_v10:
	case MAGIC_3000_v11:
	case MAGIC_3000_v12:
		return "3000";
	case MAGIC_3_0a4:
		return "3.0a4";
	case MAGIC_3_0a5:
		return "3.0a5";
	case MAGIC_3_1a0_v0:
	case MAGIC_3_1a0_v1:
		return "3.1a0";
	case MAGIC_3_2a0:
		return "3.2a0";
	case MAGIC_3_2a1:
		return "3.2a1";
	case MAGIC_3_2a2:
		return "3.2a2";
	case MAGIC_3_3a0_v0:
	case MAGIC_3_3a0_v1:
		return "3.3a0";
	case MAGIC_3_3a1:
		return "3.3a1";
	case MAGIC_3_3a4:
		return "3.3a4";
	case MAGIC_3_4a1_v0:
	case MAGIC_3_4a1_v1:
	case MAGIC_3_4a1_v2:
	case MAGIC_3_4a1_v3:
		return "3.4a1";
	case MAGIC_3_4a4_v0:
	case MAGIC_3_4a4_v1:
		return "3.4a4";
	case MAGIC_3_4rc2:
		return "3.4rc2";
	case MAGIC_3_5a0:
		return "3.5a0";
	case MAGIC_3_5b1:
		return "3.5b1";
	case MAGIC_3_5b2_v0:
	case MAGIC_3_5b2_v1:
		return "3.5b2";
	case MAGIC_3_6a0_v0:
	case MAGIC_3_6a0_v1:
		return "3.6a0";
	default:
		return NULL;
	}
}

char *get_pyc_file_type(enum pyc_magic magic) {
	char *version = get_python_version (magic);
	const char *format = "Python %s byte-compiled file";

	if (!version)
		return strdup ("Python byte-compiled file (unknown version)");
	return r_str_newf (format, version);
}

char *get_pyc_file_machine(enum pyc_magic magic) {
	char *version = get_python_version (magic);
	const char *format = "Python %s VM";

	if (!version)
		return strdup ("Python VM (unknown version)");
	return r_str_newf (format, version);
}

bool check_magic(enum pyc_magic magic) {
	return get_python_version (magic) != NULL;
}
