/* radare2 - LGPL - Copyright 2015-2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 4) {
		ut32 cls = r_mem_get_num (buf, 4);
		ut32 cls2 = r_mem_get_num (buf + 4, 4);
		if (cls + 4 == length && !cls2) {
			return true;
		}
	}
	return false;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}


static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void*)(size_t)check_bytes (buf, sz);
}

static int load(RBinFile *arch) {
	return check(arch);
}

static int destroy (RBinFile *arch) {
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 4;
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static ut64 findEntry(RBuffer *buf, int n) {
	int i;
	for (i=4;i<buf->length; i++) {
		if (buf->buf[i] != 0) {
			if (n == 0) {
				return i;
			}
			n--;
			for (++i; i<buf->length; i++) {
				if (!buf->buf[i])
					break;
			}
		}
	}
	return 0;
}

static RList* entries(RBinFile *arch) {
	RList* ret = r_list_newf (free);
	RBinAddr *ptr = NULL;
	if (ret) {
		if ((ptr = R_NEW0 (RBinAddr))) {
			ut64 entry = findEntry (arch->buf, 2);
			if (!entry) entry = findEntry (arch->buf, 1);
			if (!entry) entry = findEntry (arch->buf, 0);
			if (!entry) entry = 4;
			ptr->paddr = entry;
			ptr->vaddr = entry;
			r_list_append (ret, ptr);
		} else {
			r_list_free (ret);
			ret = NULL;
		}
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut64 textsize, datasize, symssize, spszsize, pcszsize;
	ut64 entry0 = findEntry (arch->buf, 0);
	ut64 entry1 = findEntry (arch->buf, 1);
	ut64 entry2 = findEntry (arch->buf, 2);

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	// add text segment
	textsize = r_mem_get_num (arch->buf->buf + 4, 4);
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	if (!entry1) {
		entry1 = arch->buf->length;
	}
	strncpy (ptr->name, "init", R_BIN_SIZEOF_STRINGS);
	ptr->size = entry1-entry0;
	ptr->vsize = entry1-entry0;
	ptr->paddr = entry0 + 4;
	ptr->vaddr = entry0;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	r_list_append (ret, ptr);

	if (entry1) {
		if (entry2) {
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			strncpy (ptr->name, "fini", R_BIN_SIZEOF_STRINGS);
			ptr->size = entry2-entry1;
			ptr->vsize = entry2-entry1;
			ptr->paddr = entry1 + 4;
			ptr->vaddr = entry1;
			ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
			r_list_append (ret, ptr);
		} else {
			entry2 = entry1;
		}
	}
	if (entry2) {
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
		ptr->size = arch->buf->length - entry2;
		ptr->vsize = arch->buf->length - entry2;
		ptr->paddr = entry2 + 4;
		ptr->vaddr = entry2;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* symbols(RBinFile *arch) {
	// TODO: parse symbol table
	return NULL;
}

static RList* imports(RBinFile *arch) {
	return NULL;
}

static RList* libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (arch->file);
		ret->bclass = strdup ("dna");
		ret->rclass = strdup ("bcl");
		ret->os = strdup ("Illumina DNA Sequences");
		ret->arch = strdup ("bcl");
		ret->machine = strdup (ret->arch);
		ret->subsystem = strdup ("bcl");
		ret->type = strdup ("DATA (ATCG streams)");
		ret->bits = 8;
		ret->has_va = true;
		ret->big_endian = false;
		ret->dbg_info = 0;
	}
	return ret;
}

static int size(RBinFile *arch) {
	ut64 text, data, syms, spsz;
	int big_endian;
	if (!arch->o->info) {
		arch->o->info = info (arch);
	}
	big_endian = arch->o->info->big_endian;
	// TODO: reuse section list
	text = r_mem_get_num (arch->buf->buf + 4, 4);
	data = r_mem_get_num (arch->buf->buf + 8, 4);
	syms = r_mem_get_num (arch->buf->buf + 16, 4);
	spsz = r_mem_get_num (arch->buf->buf + 24, 4);
	return text+data+syms+spsz+(6*4);
}

RBinPlugin r_bin_plugin_bcl = {
	.name = "bcl",
	.desc = "Base Call DNA Illumina",
	.license = "BSD",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.size = &size,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bcl,
	.version = R2_VERSION
};
#endif
