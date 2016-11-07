/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp/mdmp.h"

/* FIXME: Using r_list_join seems to break the lists and their freeing ability.
I am yet to determine the cause (its only a linked list!!!), but we can append
as a work around */
static int r_list_shit_join(RList *list1, RList *list2) {
	void *data;
	RListIter *it;
	r_list_foreach (list2, it, data) {
		r_list_append (list1, data);
	}
	return 1;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

static Sdb *get_sdb(RBinObject *o) {
	struct r_bin_mdmp_obj *bin;

	if (!o) return NULL;

	bin = (struct r_bin_mdmp_obj *) o->bin_obj;
	if (bin && bin->kv) return bin->kv;

	return NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_mdmp_free ((struct r_bin_mdmp_obj*)arch->o->bin_obj);

	return true;
}

static RList* entries(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RListIter *it;
	RList* ret, *list;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_entrypoint (pe32_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_entrypoint (pe64_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}

	return ret;
}

static RBinInfo *info(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	RBinInfo *ret;

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}

	ret->big_endian = obj->endian;
	ret->claimed_checksum = strdup (sdb_fmt (0, "0x%08x", obj->hdr->check_sum));
	ret->file = arch->file ? strdup (arch->file) : NULL;
	ret->has_va = true;
	ret->rpath = strdup ("NONE");
	ret->type = strdup ("MDMP (MiniDump crash report data)");

	if (obj->streams.system_info)
	{
		switch (obj->streams.system_info->processor_architecture) {
		case PROCESSOR_ARCHITECTURE_INTEL:
			ret->machine = strdup ("i386");
			ret->arch = strdup ("x86");
			ret->bits = 32;
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			ret->machine = strdup ("ARM");
			ret->big_endian = false;
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			ret->machine = strdup ("IA64");
			ret->arch = strdup ("IA64");
			ret->bits = 64;
			break;
		case PROCESSOR_ARCHITECTURE_AMD64:
			ret->machine = strdup ("AMD64");
			ret->arch = strdup ("x86");
			ret->bits = 64;
			break;
		default:
			strncpy (ret->machine, "Unknown", R_BIN_SIZEOF_STRINGS);
		}

		switch (obj->streams.system_info->product_type) {
		case VER_NT_WORKSTATION:
			ret->os = r_str_newf ("Windows NT Workstation %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		case VER_NT_DOMAIN_CONTROLLER:
			ret->os = r_str_newf ("Windows NT Server Domain Controller %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		case VER_NT_SERVER:
			ret->os = r_str_newf ("Windows NT Server %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		default:
			ret->os = strdup ("Unknown");
		}
	}

	return ret;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	RBuffer *tbuf;
	struct r_bin_mdmp_obj *res;

	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}

	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	if ((res = r_bin_mdmp_new_buf (tbuf))) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);

	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf) : 0;

	if (!arch || !arch->o) {
		return false;
	}

	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);

	return arch->o->bin_obj ? true : false;
}

static RList *sections(RBinFile *arch) {
	struct minidump_memory_descriptor *memory;
	struct minidump_memory_descriptor64 *memory64;
	struct minidump_module *module;
	struct minidump_string *str;
	struct r_bin_mdmp_obj *obj;
	RList *ret;
	RListIter *it;
	RBinSection *ptr;
	ut64 index;

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	r_list_foreach (obj->streams.memories, it, memory) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		strncpy(ptr->name, "Memory_Section", 14);
		ptr->paddr = (memory->memory).rva;
		ptr->size = (memory->memory).data_size;
		ptr->vaddr = memory->start_of_memory_range;
		ptr->vsize = (memory->memory).data_size;
		ptr->add = true;

		ptr->srwx = R_BIN_SCN_MAP;
		ptr->srwx |= r_bin_mdmp_get_srwx (obj, ptr->vaddr);

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, memory64) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		strncpy(ptr->name, "Memory_Section", 14);
		ptr->paddr = index;
		ptr->size = memory64->data_size;
		ptr->vaddr = memory64->start_of_memory_range;
		ptr->vsize = memory64->data_size;
		ptr->add = true;

		ptr->srwx = R_BIN_SCN_MAP;
		ptr->srwx |= r_bin_mdmp_get_srwx (obj, ptr->vaddr);

		r_list_append (ret, ptr);

		index += memory64->data_size;
	}

	r_list_foreach (obj->streams.modules, it, module) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		str = (struct minidump_string *)(obj->b->buf + module->module_name_rva);
		r_str_utf16_to_utf8 ((ut8 *)ptr->name, R_BIN_SIZEOF_STRINGS, (const ut8 *)&(str->buffer), str->length, obj->endian);
		ptr->vaddr = module->base_of_image;
		ptr->vsize = module->size_of_image;
		ptr->paddr = r_bin_mdmp_get_paddr (obj, ptr->vaddr);
		ptr->size = module->size_of_image;
		ptr->add = true;

		/* FIXME?: Will only set the permissions for the first section,
		** i.e. header. Should we group all the permissions together
		** and report as lets say rwx as we will contain header, .text,
		** .data, etc... */
		ptr->srwx = R_BIN_SCN_MAP;
		ptr->srwx |= r_bin_mdmp_get_srwx (obj, ptr->vaddr);

		r_list_append (ret, ptr);
	}

	return ret;
}

/* TODO: This (but better) should be in r_bin.c It already is */
/* FIXME: Why is it not mem_free static? */
static void r_bin_mem_free(void *data) {
	RBinMem *mem = (RBinMem *)data;
	if (mem && mem->mirrors) {
		mem->mirrors->free = r_bin_mem_free;
		r_list_free (mem->mirrors);
		mem->mirrors = NULL;
	}
	free (mem);
}

static RList *mem (RBinFile *arch) {
	struct minidump_location_descriptor *location;
	struct minidump_memory_descriptor *module;
	struct minidump_memory_descriptor64 *module64;
	struct r_bin_mdmp_obj *obj;
	RList *ret;
	RListIter *it;
	RBinMem *ptr;
	ut64 index;

	if (!(ret = r_list_newf (r_bin_mem_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->streams.memories, it, module) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}

		location = &(module->memory);
		ptr->name = strdup (sdb_fmt (0, "paddr=0x%08x Memory_Section", location->rva));
		ptr->addr = module->start_of_memory_range;
		ptr->size = (location->data_size);
		ptr->perms = R_BIN_SCN_MAP;
		ptr->perms |= r_bin_mdmp_get_srwx (obj, ptr->addr);

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, module64) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}

		ptr->name = strdup (sdb_fmt (0, "paddr=0x%08x Memory_Section", index));
		ptr->addr = module64->start_of_memory_range;
		ptr->size = module64->data_size;
		ptr->perms = R_BIN_SCN_MAP;
		ptr->perms |= r_bin_mdmp_get_srwx (obj, ptr->addr);

		index += module64->data_size;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* relocs(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RListIter *it;
	RList* ret;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		if (pe32_bin->bin) {
			r_list_shit_join (ret, pe32_bin->bin->relocs);
		}
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		if (pe64_bin->bin) {
			r_list_shit_join (ret, pe64_bin->bin->relocs);
		}
	}

	return ret;
}

static RList* imports(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret = NULL, *list;
	RListIter *it;

	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_imports (pe32_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_imports (pe64_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}
	return ret;
}

static RList* symbols(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret, *list;
	RListIter *it;

	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_symbols (pe32_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_symbols (pe64_bin);
		r_list_shit_join (ret, list);
		r_list_free (list);
	}

	return ret;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return buf && (length > sizeof (struct minidump_header))
		&& (!memcmp (buf, MDMP_MAGIC, 6));
}

static int check(RBinFile *arch) {
	const ut8 *bytes;
	ut64 sz;

	bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	sz = arch ? r_buf_size (arch->buf) : 0;

	return check_bytes (bytes, sz);
}

RBinPlugin r_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Minidump format r_bin plugin",
	.license = "LGPL3",
	.baddr = &baddr,
	.check = &check,
	.check_bytes = &check_bytes,
	.destroy = &destroy,
	.entries = entries,
	.get_sdb = &get_sdb,
	.imports = &imports,
	.info = &info,
	.load = &load,
	.load_bytes = &load_bytes,
	.mem = &mem,
	.relocs = &relocs,
	.sections = &sections,
	.symbols = &symbols,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdmp,
	.version = R2_VERSION
};
#endif
