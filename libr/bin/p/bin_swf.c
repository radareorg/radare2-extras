/* radare - LGPL3 - 2016 - xarkes */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/swf/swf_specs.h"
#include "../format/swf/swf.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static char compression;
static char flashVersion;

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	compression = buf[0];
	flashVersion = buf[3];
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 4) return false;

	if ((*buf == ISWF_MAGIC_0_0 || *buf == ISWF_MAGIC_0_1 ||
			*buf == ISWF_MAGIC_0_2) && (!memcmp (buf+1, ISWF_MAGIC, 2)))
		return true;

	return false;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	if(!(ret = R_NEW0 (RBinInfo)))
		return NULL;

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

struct r_bin_plugin_t r_bin_plugin_swf = {
	.name = "swf",
	.desc = "SWF",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_swf,
	.version = R2_VERSION
};
#endif
