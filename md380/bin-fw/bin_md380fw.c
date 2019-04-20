/* radare2 - LGPL - Copyright 2017-2019 - pancake */

#include <r_lib.h>
#include <r_bin.h>
#include <r_util.h>

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 32) {
		if (!strcmp ((const char *)buf, "OutSecurityBin")) {
			return true;
		}
	}
	return false;
}

static ut32 readLE32(RBuffer *buf, int off) {
	return r_buf_read_le32_at (buf, off);
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (bool)(void*)(size_t)check_bytes (buf, sz);
}

static void * load_buffer(RBinFile *arch, RBuffer *buf, ut64 loadaddr, Sdb *sdb){
	ut8 data[64];
	int data_len = r_buf_read_at (buf, 0, data, sizeof (data));
	void *bo = NULL;
	return (void*)(bool)(load_bytes (arch, &bo, data, data_len, loadaddr, sdb));
}

static bool load(RBinFile *arch) {
	ut64 sz;
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf, &sz) : NULL;
	return check_bytes (bytes, sz);
}

static ut64 baddr(RBinFile *bf) {
	ut64 vaddr = (ut64)readLE32(bf->buf, 0x80);
	return vaddr;
}

static RList* entries(RBinFile *bf) {
	RList* ret = r_list_newf (free);
	RBinAddr *ptr = NULL;
	if (ret) {
		if ((ptr = R_NEW0 (RBinAddr))) {
			ut64 entry = (ut64)readLE32(bf->buf, 0x80);
			ut64 size = (ut64)readLE32(bf->buf, 0x84);
			// eprintf ("0x%x 0x%x\n", entry, size);
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

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ut64 vaddr = (ut64)readLE32 (bf->buf, 0x80);
	ut64 psize = (ut64)readLE32(bf->buf, 0x84);
	ptr->name = strdup ("system");
	ptr->size = psize;
	ptr->arch = strdup ("arm");
	ptr->bits = 16;
	ptr->vsize = psize;
	ptr->paddr = 0x100;
	ptr->vaddr = vaddr;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);

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

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (bf->file);
		ret->bclass = strdup ("firmware");
		ret->rclass = strdup ("image");
		ret->os = strdup ("tytera");
		ret->arch = strdup ("arm");
		ret->machine = strdup (ret->arch);
		int left;
		ret->subsystem = r_buf_get_string (bf->buf, 0x10);
		ret->type = strdup ("Firmware");
		ret->bits = 16;
		ret->has_va = true;
		ret->big_endian = false;
		ret->dbg_info = 0;
	}
	return ret;
}

static ut64 size(RBinFile *arch) {
	return 0;
}

RBinPlugin r_bin_plugin_bcl = {
	.name = "md380fw",
	.desc = "TYT MD380 Firmware",
	.license = "BSD",
	.load = &load,
	.load_bytes = &load_bytes,
	.load_buffer = &load_buffer,
	.size = &size,
	// .check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bcl,
	.version = R2_VERSION
};
#endif
