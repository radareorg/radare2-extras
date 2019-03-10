/* radare - LGPL3 - Copyright 2018 - damo22 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_endian.h>
#include "../../asm/arch/atombios/atombios.h"

static ut16 header;
static ut16 mastercmdoffset;
static ut16 masterdataoffset;
static ut32 cmdtableoffs[N_TABLES_CMD];
static ut32 cmdtablesize[N_TABLES_CMD];
static ut32 datatableoffs[N_TABLES_DATA];
static ut32 datatablesize[N_TABLES_DATA];

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 0x70)
		return false;

	header = r_read_at_le16(buf, HEADER_OFFSET);
	if (memcmp (buf + header + 4, ATOM_MAGIC, 4))
		return false;

	return true;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	ut8 i;
	if (!check_bytes(buf, sz))
		return false;

	mastercmdoffset = r_read_at_le16(buf, header + 30) + 4;
	masterdataoffset = r_read_at_le16(buf, header + 32) + 4;


	for (i = 0; i < N_TABLES_CMD; i++) {
		cmdtableoffs[i] = r_read_at_le16 (buf, mastercmdoffset + i * sizeof (ut16));
		if (!cmdtableoffs[i]) {
			cmdtablesize[i] = 0;
		} else {
			cmdtablesize[i] = r_read_at_le16 (buf, cmdtableoffs[i]) - 6;
			cmdtableoffs[i] += 6;
		}
	}

	for (i = 0; i < N_TABLES_DATA; i++) {
		datatableoffs[i] = r_read_at_le16 (buf, masterdataoffset + i * sizeof (ut16));
		if (!datatableoffs[i]) {
			datatablesize[i] = 0;
		} else {
			datatablesize[i] = r_read_at_le16 (buf, datatableoffs[i]) - 4;
			datatableoffs[i] += 4;
		}
	}
	return true;
}

static bool load(RBinFile *bf) {
        const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
        ut64 sz = bf ? r_buf_size (bf->buf): 0;

        if (!bf || !bf->o) {
                return false;
        }
        return load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
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
	ret->dbg_info = 0;
	ret->has_nx = false;

	return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
        RBinSymbol *ptr = R_NEW0 (RBinSymbol);
        if (!ptr) return;
        ptr->name = strdup (name? name: "");
        ptr->paddr = ptr->vaddr = addr;
        ptr->size = size;
        ptr->ordinal = 0;
        r_list_append (ret, ptr);
}

static RList* symbols(RBinFile *bf) {
	ut8 i;
        RList *ret = NULL;
        if (!(ret = r_list_newf (free))) {
                return NULL;
        }

	/* Data table symbols */
	for (i = 0; i < N_TABLES_DATA; i++) {
		if (datatableoffs[i])
			addsym (ret, index_data_table[i], datatableoffs[i], datatablesize[i]);
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	ut8 i;
	ut16 sz = 0;
	RList *ret = NULL;
	RBinSection *sect;

	if (!(ret = r_list_new()))
		return NULL;

	/* Command table sections */
	for (i = 0; i < N_TABLES_CMD; i++) {
		sz = cmdtablesize[i];
		if (!(sect = R_NEW0 (RBinSection))) {
			return false;
		}
		if (cmdtableoffs[i]) {
			strcpy (sect->name, index_command_table[i]);
			sect->paddr = cmdtableoffs[i];
			sect->vaddr = cmdtableoffs[i];
			sect->size = sz;
			sect->vsize = sz;
			sect->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE;
			r_list_append (ret, sect);
		} else {
			strcpy (sect->name, "dummy");
			sect->paddr = 0;
			sect->vaddr = 0;
			sect->size = 0;
			sect->vsize = 0;
			sect->srwx = 0;
			r_list_append (ret, sect);
		}
	}

	/* Data table sections */
	for (i = 0; i < N_TABLES_DATA; i++) {
		sz = datatablesize[i];
		if (!(sect = R_NEW0 (RBinSection))) {
			return false;
		}
		if (datatableoffs[i]) {
			strcpy (sect->name, index_data_table[i]);
			sect->paddr = datatableoffs[i];
			sect->vaddr = datatableoffs[i];
			sect->size = sz;
			sect->vsize = sz;
			sect->srwx = R_BIN_SCN_READABLE;
			r_list_append (ret, sect);
		} else {
			strcpy (sect->name, "dummy");
			sect->paddr = 0;
			sect->vaddr = 0;
			sect->size = 0;
			sect->vsize = 0;
			sect->srwx = 0;
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

	ptr->paddr = cmdtableoffs[0];
	ptr->vaddr = cmdtableoffs[0];
	r_list_append(ret, ptr);

	return ret;
}

RBinPlugin r_bin_plugin_atombios = {
	.name = "atombios",
	.desc = "AtomBIOS",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_atombios,
	.version = R2_VERSION
};
#endif
