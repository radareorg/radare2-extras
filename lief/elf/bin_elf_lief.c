/* radare - MIT - Copyright 2017 - pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <inttypes.h>
#include <LIEF/ELF.h>

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	// in case of fail, LIEF throws a c++ exception, so everybody dies
	// LIEF doesnt supports parsing binaries from buffers wtf
	return elf_parse (arch->file);
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
	Elf_Binary_t *elf = arch->o->bin_obj;
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = "c";
	ret->file = arch->file ? strdup (arch->file) : NULL;

	// XXX enums are not available at C level... wtf
	switch (elf->header.machine_type) {
	case 1: // ARCH_ARM:
		ret->arch = strdup ("arm");
		ret->bits = 32;
		break;
	case 2: // ARCH_ARM64:
		ret->arch = strdup ("arm");
		ret->bits = 64;
		break;
	case 3: // ARCH_MIPS:
		ret->arch = strdup ("mips");
		ret->bits = 64;
		break;
	case 4: // ARCH_X86:
		ret->arch = strdup ("x86");
		ret->bits = 32;
		break;
	case 0x3e: // ARCH_X86_64:
		ret->arch = strdup ("x86");
		ret->bits = 64;
		break;
	default:
		if (1) {
			const char *str = ARCH_to_string (elf->header.machine_type);
			eprintf ("Unknown arch 0x%x %s\n", elf->header.machine_type, str);
		}
		break;
	}
	const ut8 *identity = elf->header.identity;
	ret->rclass = strdup ("elf");
	ret->intrp = strdup (elf->interpreter);
	ret->has_va = true;
	// ret->baddr = 0x40000;
	ret->has_canary = false;
	int i;
	Elf_DynamicEntry_t **dynamic_entries = elf->dynamic_entries;
	for (i = 0; dynamic_entries[i]; i++) {
		Elf_DynamicEntry_t* entry = dynamic_entries[i];
		switch (entry->tag) {
		case DT_RUNPATH:
			{
				Elf_DynamicEntry_RunPath_t* e = (Elf_DynamicEntry_RunPath_t*)entry;
				ret->rpath = strdup (e->runpath);;
			}
			break;
		default:
			break;
		}
	}
	ret->has_lit = true;
#if 0
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_canary = has_canary (arch);
	ret->bclass = str;
	ret->os = str;
	ret->subsystem = str;
	ret->machine = str;
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (arch->o->bin_obj);
	ret->has_nx = Elf_(r_bin_elf_has_nx) (arch->o->bin_obj);
	ret->dbg_info = 0;
#endif
	return ret;
}

static RList* symbols(RBinFile *arch) {
	int i;
	Elf_Binary_t *elf = arch->o->bin_obj;
	Elf_Symbol_t** dsym = elf->dynamic_symbols;
	RList *ret = r_list_newf (free);
	for (i = 0; dsym[i]; i++) {
		Elf_Symbol_t* sym = dsym[i];
		if (!sym->name || !*sym->name || !sym->value) {
			continue;
		}
		RBinSymbol *rs = R_NEW0 (RBinSymbol);
		rs->name = strdup (sym->name);
		rs->paddr = sym->value;
		rs->vaddr = sym->value;
		r_list_append (ret, rs);
	}
	return ret;
}

static RList* imports(RBinFile *arch) {
	int i;
	Elf_Binary_t *elf = arch->o->bin_obj;
	Elf_Symbol_t** dsym = elf->dynamic_symbols;
	RList *ret = r_list_newf (free);
	for (i = 0; dsym[i]; i++) {
		Elf_Symbol_t* sym = dsym[i];
		if (!sym->name || !*sym->name || sym->value) {
			continue;
		}
		RBinImport *rs = R_NEW0 (RBinImport);
		rs->name = strdup (sym->name);
		rs->type = strdup ("");
		rs->bind = strdup ("GLOBAL");
		r_list_append (ret, rs);
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	Elf_Binary_t *elf = arch->o->bin_obj;
	RList *ret = r_list_newf (free);
	int i;
	Elf_Segment_t** segments = elf->segments;
	for (i = 0; segments[i] ; i++) {
		Elf_Segment_t* seg= segments[i];
		RBinSection *rs = R_NEW0 (RBinSection);
		const char *name = SEGMENT_TYPES_to_string (seg->type);
		strcpy (rs->name, name);
		if (strstr (rs->name, "data") && !strstr (rs->name, "rel")) {
			rs->is_data = true;
		}
		rs->paddr = seg->offset;
		rs->vaddr = seg->virtual_address;
		rs->size = seg->size;
		rs->vsize = seg->virtual_size;
		rs->srwx = seg->flags;
		if (rs->vaddr) { //!strncmp (rs->name, "LOAD", 4)) {
			rs->srwx |= R_BIN_SCN_MAP;
			rs->add = true;
		}
		r_list_append (ret, rs);
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret = r_list_newf (free);
	Elf_Binary_t *elf = arch->o->bin_obj;
	RBinAddr *ptr = NULL;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->vaddr = elf->header.entrypoint;
	ptr->paddr = elf->header.entrypoint & 0xFFFF;
	ptr->haddr = 0x18;
	r_list_append (ret, ptr);
	return ret;
}

static RList* libs(RBinFile *arch) {
	int i;
	Elf_Binary_t *elf = arch->o->bin_obj;
	Elf_DynamicEntry_t **dynamic_entries = elf->dynamic_entries;
	RList *ret = r_list_newf (free);
	for (i = 0; dynamic_entries[i]; i++) {
		Elf_DynamicEntry_t* entry = dynamic_entries[i];
		switch (entry->tag) {
		case DT_NEEDED:
			{
				Elf_DynamicEntry_Library_t* e = (Elf_DynamicEntry_Library_t*)entry;
				r_list_append (ret, strdup (e->name));
			}
			break;
		}
	}
	return ret;
}

RBinPlugin r_bin_plugin_elf_lief = {
	.name = "elf.lief",
	.desc = "ELF bin plugin using LIEF",
	.license = "MIT",
	.load = &load,
	.load_bytes = &load_bytes,
	.info = &info,
	.symbols = &symbols,
	.imports = &imports,
	.sections = &sections,
	.libs = &libs,
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
	.data = &r_bin_plugin_elf_lief,
	.version = R2_VERSION
};
#endif
