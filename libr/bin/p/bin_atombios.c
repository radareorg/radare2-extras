/* radare - LGPL3 - Copyright 2018 - damo22 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_endian.h>
#include "../../asm/arch/atombios/atombios.h"
#include "atombios.h"

static ut16 header;
static ut16 mastercmdoffset;
static ut16 masterdataoffset;
static ut32 cmdtableoffs[N_TABLES_CMD];
static ut32 cmdtablesize[N_TABLES_CMD];
static ut32 datatableoffs[N_TABLES_DATA];
static ut32 datatablesize[N_TABLES_DATA];

static bool check_buffer(RBuffer *b) {
	if (!b || r_buf_size (b) < 0x70)
		return false;

	ut8 magic[4] = {0};
	header = r_buf_read_le16_at (b, HEADER_OFFSET);
	r_buf_read_at (b, header + 4, magic, 4);
	if (memcmp (magic, ATOM_MAGIC, 4))
		return false;

	return true;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	if (!check_buffer(b))
		return false;

	ut8 i;
	atombios_obj_t *obj = R_NEW0 (atombios_obj_t);
	if (!obj) {
		return false;
	} else {
		obj->b = r_buf_ref (b);
                *bin_obj = obj;
	}

	mastercmdoffset = r_buf_read_le16_at (b, header + 30) + 4;
	masterdataoffset = r_buf_read_le16_at (b, header + 32) + 4;

	for (i = 0; i < N_TABLES_CMD; i++) {
		cmdtableoffs[i] = r_buf_read_le16_at (b, mastercmdoffset + i * sizeof (ut16));
		if (!cmdtableoffs[i]) {
			cmdtablesize[i] = 0;
		} else {
			cmdtablesize[i] = r_buf_read_le16_at (b, cmdtableoffs[i]);
		}
	}

	for (i = 0; i < N_TABLES_DATA; i++) {
		datatableoffs[i] = r_buf_read_le16_at (b, masterdataoffset + i * sizeof (ut16));
		if (!datatableoffs[i]) {
			datatablesize[i] = 0;
		} else {
			datatablesize[i] = r_buf_read_le16_at (b, datatableoffs[i]);
		}
	}
	return true;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("AtomBIOS");
	ret->rclass = strdup ("atombios");
	ret->type = strdup ("AtomBIOS Video BIOS ROM");
	ret->machine = strdup ("atombios");
	ret->os = strdup ("any");
	ret->arch = strdup ("atombios");
	ret->bits = 32;
	ret->has_va = false;
	ret->dbg_info = 1;
	ret->has_nx = false;

	return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) return;
	ptr->name = strdup (name? name: "dummy");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList* symbols(RBinFile *bf) {
	ut8 i;
        RList *ret = NULL;
        if (!(ret = r_list_newf (free)))
                return NULL;

	/* Data table symbols */
	for (i = 0; i < N_TABLES_DATA; i++) {
		if (datatablesize[i])
			addsym (ret, index_data_table[i], datatableoffs[i] + 4, datatablesize[i] - 4);
	}

	/* Command table symbols */
	for (i = 0; i < N_TABLES_CMD; i++) {
		if (cmdtablesize[i])
			addsym (ret, index_command_table[i], cmdtableoffs[i] + 6, cmdtablesize[i] - 6);
	}

	return ret;
}

static RList* sections(RBinFile *bf) {
	ut8 i;
	ut16 sz = 0;
	RList *ret = NULL;
	RBinSection *sect;
	//RBuffer *b = bf->o->bin_obj;

	if (!(ret = r_list_newf (free)))
		return NULL;

	/* Command table sections */
	for (i = 0; i < N_TABLES_CMD; i++) {
		sz = cmdtablesize[i];
		if (!(sect = R_NEW0 (RBinSection))) {
			return NULL;
		}
		if (cmdtableoffs[i]) {
			sect->name = strdup (index_command_table[i]);
			sect->paddr = cmdtableoffs[i];
			sect->vaddr = cmdtableoffs[i];
			sect->size = sz;
			sect->vsize = sz;
			//TODO sect->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE;
			r_list_append (ret, sect);
		} else {
			sect->name = strdup ("dummy");
			sect->paddr = 0;
			sect->vaddr = 0;
			sect->size = 0;
			sect->vsize = 0;
			r_list_append (ret, sect);
		}
	}

	/* Data table sections */
	for (i = 0; i < N_TABLES_DATA; i++) {
		sz = datatablesize[i];
		if (!(sect = R_NEW0 (RBinSection))) {
			return NULL;
		}
		if (datatableoffs[i]) {
			sect->name = strdup (index_data_table[i]);
			sect->paddr = datatableoffs[i];
			sect->vaddr = datatableoffs[i];
			sect->size = sz;
			sect->vsize = sz;
			//TODO sect->srwx = R_BIN_SCN_READABLE;
			r_list_append (ret, sect);
		} else {
			sect->name = strdup ("dummy");
			sect->paddr = 0;
			sect->vaddr = 0;
			sect->size = 0;
			sect->vsize = 0;
			r_list_append (ret, sect);
		}
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret = NULL;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;

	ptr->paddr = cmdtableoffs[0] + 6;
	ptr->vaddr = cmdtableoffs[0] + 6;
	r_list_append(ret, ptr);

	return ret;
}

RBinPlugin r_bin_plugin_atombios = {
	.name = "atombios",
	.desc = "AtomBIOS binary format parser",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_atombios,
	.version = R2_VERSION,
	.pkgname = "atombios",
};
#endif
