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
static ut16 cmdtableoffs[N_TABLES_CMD];
static ut16 cmdtablesize[N_TABLES_CMD];

static int check_bytes(const ut8 *buf, ut64 length) {
	ut8 i;

	if (!buf || length < 0x70)
		return false;

	if (memcmp (buf + header + 4, ATOM_MAGIC, 4))
		return false;

	for (i = 0; i < N_TABLES_CMD; i++) {
		if (cmdtableoffs[i] + cmdtablesize[i] > length)
			return false;
	}

	return true;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	ut8 i;
	header = r_read_at_le16(buf, HEADER_OFFSET);
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
	check_bytes(buf, sz);
	return R_NOTNULL;
}

static bool load(RBinFile *bf) {
        const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
        ut64 sz = bf ? r_buf_size (bf->buf): 0;

        if (!bf || !bf->o) {
                return false;
        }
        bf->o->bin_obj = load_bytes (bf, bytes, sz, bf->o->loadaddr, bf->sdb);
        return bf->o->bin_obj ? true: false;
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

static RList* sections(RBinFile *arch) {
	ut8 i;
	ut16 sz = 0;
	RList *ret = NULL;

	if (!(ret = r_list_new()))
		return NULL;

	/* Command table section */
	RBinSection *cmd_sect;

	for (i = 0; i < N_TABLES_CMD; i++) {
		sz = cmdtablesize[i];
		if (!(cmd_sect = R_NEW0 (RBinSection))) {
			return false;
		}
		if (cmdtableoffs[i]) {
			strcpy (cmd_sect->name, index_command_table[i]);
			cmd_sect->paddr = cmdtableoffs[i];
			cmd_sect->vaddr = cmdtableoffs[i];
			cmd_sect->size = sz; 
			cmd_sect->vsize = sz;
			cmd_sect->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE;
			r_list_append (ret, cmd_sect);
		} else {
			strcpy (cmd_sect->name, index_command_table[i]);
			cmd_sect->paddr = 0;
			cmd_sect->vaddr = 0;
			cmd_sect->size = 0;
			cmd_sect->vsize = 0;
			cmd_sect->srwx = 0;
			r_list_append (ret, cmd_sect);
		}
	}

	/*
	 * Data table section
	RBinSection *data_sect;
	if (!(data_sect = R_NEW0 (RBinSection))) {
		return false;
	}
	strcpy (data_sect->name, "Data tables");
	data_sect->paddr = HEADER_OFFSET + masterdataoffset;
	data_sect->vaddr = HEADER_OFFSET + masterdataoffset;
	ut8 sz = 0x2;
	data_sect->size = sz;
	data_sect->vsize = sz;
	data_sect->srwx = R_BIN_SCN_READABLE;
	r_list_append (ret, data_sect);
	*/

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
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_atombios,
	.version = R2_VERSION
};
#endif
