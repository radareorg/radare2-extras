/* radare - MIT - Copyright 2017 - pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <inttypes.h>
#include <LIEF/PE.h>

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	// in case of fail, LIEF throws a c++ exception, so everybody dies
	// LIEF doesnt supports parsing binaries from buffers wtf
	return pe_parse (arch->file);
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) {
		return false;
	}
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj != NULL;
}

static RBinInfo* info(RBinFile *arch) {
	Pe_Binary_t *pe = arch->o->bin_obj;
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = "c";
	ret->file = arch->file ? strdup (arch->file) : NULL;

	// XXX enums are not available at C level... wtf
	ret->rclass = strdup ("pe");
	ret->has_va = true;
	// ret->baddr = 0x40000;
	ret->has_canary = false;
	ret->has_lit = true;
#if 0
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_canary = has_canary (arch);
	ret->bclass = str;
	ret->os = str;
	ret->subsystem = str;
	ret->machine = str;
	ret->big_endian = Pe_(r_bin_elf_is_big_endian) (arch->o->bin_obj);
	ret->has_nx = Pe_(r_bin_elf_has_nx) (arch->o->bin_obj);
	ret->dbg_info = 0;
#endif
	return ret;
}

static RList* symbols(RBinFile *arch) {
	return NULL;
}

static RList* imports(RBinFile *arch) {
	return NULL;
}

static RList* sections(RBinFile *arch) {
	return NULL;
}

static RList* entries(RBinFile *arch) {
	return NULL;
}

RBinPlugin r_bin_plugin_pe_lief = {
	.name = "pe.lief",
	.desc = "PE bin plugin using LIEF",
	.license = "MIT",
	.load = &load,
	.load_bytes = &load_bytes,
	.info = &info,
	.symbols = &symbols,
	.imports = &imports,
	.sections = &sections,
	// .libs = &libs,
	.entries = &entries,
/*
	TODO

	.get_sdb = &get_sdb,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.minstrlen = 4,
	.fields = &fields,
	.header = &headers32,
	.size = &size,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.dbginfo = &r_bin_dbginfo_elf,
	.create = &create,
	.write = &r_bin_write_elf,
*/
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe_lief,
	.version = R2_VERSION
};
#endif
