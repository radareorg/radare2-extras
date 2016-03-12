/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#include <r_bin.h>
#include "pyc.h"

static ut32 magic;

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 8) // magic + timestamp
		return false;
	memcpy (&magic, buf, sizeof (magic));
	return check_magic (magic);
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 size = arch ? r_buf_size (arch->buf) : 0;
	return check_bytes (bytes, size);
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = get_pyc_file_type (magic);
	ret->bclass = strdup ("Python byte-compiled file");
	ret->rclass = strdup ("pyc");
	ret->machine = get_pyc_file_machine (magic);
	ret->os = strdup ("any");
	ret->bits = 32;
	return ret;
}

RBinPlugin r_bin_plugin_pyc = {
	.name = "pyc",
	.desc = "Python byte-compiled file plugin",
	.license = "LGPL3",
	.info = &info,
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pyc,
	.version = R2_VERSION,
};
#endif
