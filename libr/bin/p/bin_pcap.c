#include <r_bin.h>
#include <r_lib.h>
#include "pcap.h"

#define OPP_ENDIAN  1
#define SAME_ENDIAN 0

// The pcap object for RBinFile
typedef struct pcap_obj {
	struct pcap_file_hdr header;	// File header
	bool   is_nsec;					// nsec timestamp resolution?
	int    endian; // Relative endianness (same or different from host)
	RList /*ut64*/ *pkts;			// Packet offsets
} pcap_obj_t;


// Functions

static RBinInfo* info(RBinFile *arch) {
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	RBinInfo *ret = R_NEW0(RBinInfo);
	if (!ret) {
		return NULL;
	}
	pcap_file_hdr_t *header = &((pcap_obj_t*) arch->o->bin_obj)->header;
	ret->file = strdup (arch->file);
	ret->type = r_str_newf ("pcap v%d.%d file", header->version_major,
							header->version_minor);
	ret->rclass = strdup ("pcap");
	return ret;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < sizeof (pcap_file_hdr_t) || length == UT64_MAX) {
		return false;
	}
	pcap_file_hdr_t *header = (pcap_file_hdr_t*) buf;
	switch (header->magic) {
	case PCAP_MAGIC:
	case PCAP_NSEC_MAGIC:
		return true;
	}
	switch (r_swap_ut32 (header->magic)) {
	case PCAP_MAGIC:
	case PCAP_NSEC_MAGIC:
		return true;
	}
	return false;
}

static bool check(RBinFile *arch) {
	const ut8 *bytes = arch? r_buf_buffer (arch->buf) : NULL;
	ut64 size = arch ? r_buf_size (arch->buf) : 0;
	return check_bytes (bytes, size);
}

static void* load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (!buf || !sz || sz < sizeof (pcap_file_hdr_t) || sz == UT64_MAX) {
		return NULL;
	}
	struct pcap_obj *obj = NULL;
	if (!(obj = R_NEW0 (pcap_obj_t))) {
		return NULL;
	}
	memcpy (&obj->header, buf, sizeof (pcap_file_hdr_t));

	obj->endian = SAME_ENDIAN;
	switch (obj->header.magic) {
	case PCAP_MAGIC:
		obj->is_nsec = false;
		break;
	case PCAP_NSEC_MAGIC:
		obj->is_nsec = true;
		break;
	default:
		switch (r_swap_ut32 (obj->header.magic)) {
		case PCAP_MAGIC:
			obj->is_nsec = false;
			break;
		case PCAP_NSEC_MAGIC:
			obj->is_nsec = true;
			break;
		default:
			free (obj);
			return NULL;
		}
		obj->endian = OPP_ENDIAN;
	}
	if (obj->endian == OPP_ENDIAN) {
	}
	return obj;
}

static bool load(RBinFile *arch) {
	if (!arch || !arch->o) {
		return false;
	}
	if (!check (arch)) {
		return false;
	}
	const ut8 *bytes = r_buf_buffer (arch->buf);
	ut64 size = r_buf_size (arch->buf);
	return true;
}

RBinPlugin r_bin_plugin_pcap = {
    .name = "pcap",
    .desc = "libpcap .pcap format r2 plugin",
    .license = "LGPL3",
    .info = info,
    .load = load,
    .load_bytes = load_bytes,
    .check = check,
    .check_bytes= check_bytes,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pcap,
	.version = R2_VERSION,
};
#endif
