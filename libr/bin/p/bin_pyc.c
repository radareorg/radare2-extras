/* radare - LGPL3 - Copyright 2016-2017 - Matthieu (c0riolis) Tardy */

#include <r_bin.h>
#include "pyc_magic.h"
#include "pyc.h"

// XXX: to not use globals

static struct pyc_version version;
/* used from marshall.c */
RList *interned_table = NULL;

static bool check_buffer(RBuffer *b) {
    if (r_buf_size (b) > 4) {
        ut32 buf;
        r_buf_read_at (b, 0, (ut8 *) &buf, sizeof (buf));
        version = get_pyc_version (buf);
        return version.magic != -1;
    }
    return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf,  ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = r_str_newf ("Python %s byte-compiled file", version.version);
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
	if (!shared) {
		return NULL;
	}
	RList *cobjs = r_list_new ();
	if (!cobjs) {
		return NULL;
	}
	interned_table = r_list_new ();
	if (!interned_table) {
		return NULL;
	}
	r_list_append (shared, cobjs);
	r_list_append (shared, interned_table);
	arch->o->bin_obj = shared;
	RList *sections = r_list_new ();
	if (!sections) {
		return NULL;
	}
	pyc_get_sections (sections, cobjs, arch->buf, version.magic);
	return sections;
}

static RList *entries(RBinFile *arch) {
	RList *entries = r_list_new ();
	if (!entries) {
		return NULL;
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		return NULL;
	}
	ut64 entrypoint = pyc_get_entrypoint (version.magic);
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	r_buf_seek (arch->buf, entrypoint, R_IO_SEEK_CUR);
	r_list_append (entries, addr);
	return entries;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_pyc = {
	.name = "pyc",
	.desc = "Python byte-compiled file plugin",
	.license = "LGPL3",
	.info = &info,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.baddr = &baddr,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pyc,
	.version = R2_VERSION,
};
#endif
