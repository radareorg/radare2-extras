/* radare - LGPL3 - 2016-2020 - xarkes */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/swf/swf_specs.h"
#include "../format/swf/swf.h"

static bool check_buffer(RBuffer *b);

static char compression;
static char flashVersion;

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	if (check_buffer (b)) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, 4);
		compression = buf[0];
		flashVersion = buf[3];
		return true;
	}
	return false;
}

static bool check_buffer(RBuffer *b) {
	ut8 buf[4];
	if (r_buf_size (b) < 4) {
		return false;
	}
	r_buf_read_at (b, 0, buf, 4);
	switch (buf[0]) {
	case ISWF_MAGIC_0_0:
	case ISWF_MAGIC_0_1:
	case ISWF_MAGIC_0_2:
		if (!memcmp (buf + 1, ISWF_MAGIC, 2)) {
			return true;
		}
		break;
	}

	return false;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("SWF");
	ret->rclass = strdup ("swf");
	ret->type = get_swf_file_type (compression, flashVersion);
	ret->machine = strdup ("i386");
	ret->os = strdup ("any");
	ret->arch = strdup ("swf");
	ret->bits = 32;
	ret->has_va = false;
	ret->dbg_info = 0;
	ret->has_nx = false;

	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;

	if (!(ret = r_list_new()))
		return NULL;

	r_bin_swf_get_sections(ret, arch);

	return ret;
}

static RList* entries(RBinFile *arch) { 
	RList *ret = NULL;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;

	swf_hdr header;
	header = r_bin_swf_get_header(arch);

	if (compression == ISWF_MAGIC_0_0) {
		ptr->paddr = header.rect_size + SWF_HDR_MIN_SIZE;
		ptr->vaddr = header.rect_size + SWF_HDR_MIN_SIZE;
	} else {
		ptr->paddr = 0x08;
		ptr->vaddr = 0x08;
	}

	r_list_append(ret, ptr);

	return ret;
}

RBinPlugin r_bin_plugin_swf = {
	.name = "swf",
	.desc = "SWF",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_swf,
	.version = R2_VERSION,
	.pkgname = "swf"
};
#endif
