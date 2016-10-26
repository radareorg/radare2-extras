/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp/mdmp.h"


static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);


static ut64 baddr(RBinFile *arch) {
	return r_bin_mdmp_get_baddr (arch->o->bin_obj);
}

static Sdb *get_sdb(RBinObject *o) {
	struct r_bin_mdmp_obj *bin;

	if (!o) return NULL;

	bin = (struct r_bin_mdmp_obj *) o->bin_obj;
	if (bin->kv) return bin->kv;

	return NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_mdmp_free ((struct r_bin_mdmp_obj*)arch->o->bin_obj);

	return true;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	RBuffer *tbuf;
	void *res;

	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}

	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_mdmp_new_buf (tbuf);
	r_buf_free (tbuf);
	return res;
}

static RBinInfo *info(RBinFile *arch) {
	struct r_bin_mdmp_obj *obj;
	RBinInfo *ret;

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	ret = R_NEW0 (RBinInfo);
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

static int load(RBinFile *arch) {
	const ut8 *bytes;
	ut64 sz;

	if (!arch || !arch->o) {
		return false;
	}

	bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	sz = arch ? r_buf_size (arch->buf) : 0;
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);

	return arch->o->bin_obj ? true : false;
}

static RList *sections(RBinFile *arch) {
	struct minidump_module *module;
	struct minidump_string *str;
	struct r_bin_mdmp_obj *obj;
	RList *ret;
	RListIter *it;
	RBinSection *ptr;

	struct minidump_memory_descriptor64 *memory64;
	RListIter *mem_it;
	RBinMem *mem_ptr;
	ut64 index;

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	r_list_foreach (obj->streams.modules, it, module) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		str = (struct minidump_string *)(obj->b->buf + module->module_name_rva);
		r_str_utf16_to_utf8 ((ut8 *)ptr->name, R_BIN_SIZEOF_STRINGS, (const ut8 *)&(str->buffer), str->length, obj->endian);
		ptr->size = module->size_of_image;
		ptr->vsize = module->size_of_image;
		ptr->paddr = 0;
		ptr->vaddr = module->base_of_image;
		ptr->add = true;
		ptr->srwx = 0;

		/* Loop through the memories sections looking for a match */
		index = obj->streams.memories64.base_rva;
		r_list_foreach (obj->streams.memories64.memories, mem_it, memory64) {
			if (!(mem_ptr = R_NEW0 (RBinMem))) {
				return ret;
			}

			if (ptr->vaddr == memory64->start_of_memory_range) {
				ptr->paddr = index;
				break;
			}
			index += memory64->data_size;
		}

		r_list_append (ret, ptr);
	}

	return ret;
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

	if (!(ret = r_list_new ()))
		return NULL;

	obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	r_list_foreach (obj->streams.memories, it, module) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}

		/* FIXME: Hacky approach to match memory from virtual address to location in buffer */
		location = &(module->memory);
		ptr->name = strdup (sdb_fmt (0, "paddr=0x%08x RAM", location->rva));
		ptr->addr = module->start_of_memory_range;
		ptr->size = (location->data_size);
		ptr->perms = r_str_rwx ("---");

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, module64) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}

		/* FIXME: Hacky approach to match memory from virtual address to location in buffer */
		ptr->name = strdup (sdb_fmt (0, "paddr=0x%08x RAM", index));
		ptr->addr = module64->start_of_memory_range;
		ptr->size = module64->data_size;
		ptr->perms = r_str_rwx ("---");

		index += module64->data_size;

		r_list_append (ret, ptr);
	}

	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes;
	ut64 sz;

	bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	sz = arch ? r_buf_size (arch->buf) : 0;

	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return buf && (length > sizeof (struct minidump_header))
		&& (!memcmp (buf, MDMP_MAGIC, 6));
}

RBinPlugin r_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Minidump format r_bin plugin",
	.license = "LGPL3",
	.baddr = &baddr,
	.check = &check,
	.check_bytes = &check_bytes,
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.info = &info,
	.load = &load,
	.load_bytes = &load_bytes,
	.mem = &mem,
	.sections = &sections,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdmp,
	.version = R2_VERSION
};
#endif
