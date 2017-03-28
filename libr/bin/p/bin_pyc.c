/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#include <r_bin.h>
#include "pyc_magic.h"
#include "pyc.h"

static struct pyc_version version;
RList *interned_table = NULL;

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 8) // magic + timestamp
		return false;
	version = get_pyc_version (*(ut32*)buf);
	return version.magic != -1;
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
	ret->type = r_str_newf ("Python %s%s byte-compiled file", version.version,
				version.unicode ? " Unicode" : "");
	ret->bclass = strdup ("Python byte-compiled file");
	ret->rclass = strdup ("pyc");
	ret->machine = r_str_newf ("Python %s VM (rev %s)", version.version,
				version.revision);
	ret->os = strdup ("any");
	ret->bits = 32;
	return ret;
}

static RList *sections(RBinFile *arch) {
	RList *shared = r_list_new ();
	RList *cobjs = r_list_new ();

	interned_table = r_list_new ();
	r_list_append(shared, cobjs);
	r_list_append(shared, interned_table);
	arch->o->bin_obj = shared;
	RList *sections = r_list_new ();
	if (!sections)
		return NULL;
	pyc_get_sections (sections, cobjs, arch->buf, version.magic);
	return sections;
}

static RList *entries(RBinFile *arch) {
	RList *entries = r_list_new ();
	RBinAddr *addr = R_NEW0 (RBinAddr);
	ut64 entrypoint = pyc_get_entrypoint (version.magic);
	if (!entries || !addr)
		return NULL;
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	r_buf_seek (arch->buf, entrypoint, R_IO_SEEK_CUR);
	r_list_append (entries, addr);
	return entries;
}

RBinPlugin r_bin_plugin_pyc = {
	.name = "pyc",
	.desc = "Python byte-compiled file plugin",
	.license = "LGPL3",
	.info = &info,
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pyc,
	.version = R2_VERSION,
};
#endif
