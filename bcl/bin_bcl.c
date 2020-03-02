/* radare2 - LGPL - Copyright 2015-2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool __check_buffer(RBuffer *b) {
	ut8 buf[8];
	int length = r_buf_size (b);
	int r = r_buf_read_at (b, 0, buf, sizeof (buf));
	if (r == sizeof (buf)) {
		ut32 cls = r_mem_get_num (buf, 4);
		ut32 cls2 = r_mem_get_num (buf + 4, 4);
		if (cls + 4 == length && !cls2) {
			return true;
		}
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return __check_buffer (buf);
}

static ut64 baddr(RBinFile *bf) {
	return 4;
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	return NULL; // TODO
}

static ut64 findEntry(RBuffer *buf, int n) {
	ut8 b;
	ut64 buf_size = r_buf_size (buf);
	int i;
	for (i = 4; i < buf_size; i++) {
		if (r_buf_read_at (buf, i, &b, 1) != 1) {
			break;
		}
		if (b != 0) {
			if (n == 0) {
				return i;
			}
			n--;
			for (++i; i < buf_size && b; i++) {
				if (r_buf_read_at (buf, i, &b, 1) != 1) {
					break;
				}
			}
		}
	}
	return 0;
}

static RList* entries(RBinFile *bf) {
	RList* ret = r_list_newf (free);
	RBinAddr *ptr = NULL;
	if (ret) {
		if ((ptr = R_NEW0 (RBinAddr))) {
			ut64 entry = findEntry (bf->buf, 2);
			if (!entry) entry = findEntry (bf->buf, 1);
			if (!entry) entry = findEntry (bf->buf, 0);
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

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut64 textsize, datasize, symssize, spszsize, pcszsize;
	ut64 entry0 = findEntry (bf->buf, 0);
	ut64 entry1 = findEntry (bf->buf, 1);
	ut64 entry2 = findEntry (bf->buf, 2);

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	// add text segment
	ut8 str[4] = {0};
	r_buf_read_at (bf->buf, 4, str, 4);
	textsize = r_mem_get_num (str, 4);
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	if (!entry1) {
		entry1 = r_buf_size (bf->buf);
	}
	ptr->name = strdup ("init");
	ptr->size = entry1 - entry0;
	ptr->vsize = entry1 - entry0;
	ptr->paddr = entry0 + 4;
	ptr->vaddr = entry0;
	ptr->add = true;
	ptr->perm = R_PERM_RX;
	r_list_append (ret, ptr);

	if (entry1) {
		if (entry2) {
			if (!(ptr = R_NEW0 (RBinSection))) {
				return ret;
			}
			ptr->name = strdup ("fini");
			ptr->size = entry2 - entry1;
			ptr->vsize = entry2 - entry1;
			ptr->paddr = entry1 + 4;
			ptr->vaddr = entry1;
			ptr->perm = R_PERM_RX;
			ptr->add = true;
			r_list_append (ret, ptr);
		} else {
			entry2 = entry1;
		}
	}
	if (entry2) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("text");
		ut64 filesize = r_buf_size (bf->buf);
		ptr->size = filesize - entry2;
		ptr->vsize = filesize - entry2;
		ptr->paddr = entry2 + 4;
		ptr->vaddr = entry2;
		ptr->perm = R_PERM_RX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (bf->file);
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

static ut64 size(RBinFile *bf) {
	if (!bf->o->info) {
		bf->o->info = info (bf);
	}
	ut8 str[32] = {0};
	r_buf_read_at (bf->buf, 0, str, 32);
	// TODO: reuse section list
	ut64 text = r_mem_get_num (str + 4, 4);
	ut64 data = r_mem_get_num (str + 8, 4);
	ut64 syms = r_mem_get_num (str + 16, 4);
	ut64 spsz = r_mem_get_num (str + 24, 4);
	return text + data + syms + spsz + (6 * 4);
}

RBinPlugin r_bin_plugin_bcl = {
	.name = "bcl",
	.desc = "Base Call DNA Illumina",
	.license = "BSD",
	.load_buffer = &load_buffer,
	.check_buffer = &__check_buffer,
	.size = &size,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bcl,
	.version = R2_VERSION
};
#endif
