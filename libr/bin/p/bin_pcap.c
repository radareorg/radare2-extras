#include <r_bin.h>
#include <r_lib.h>

#include "pcap.h"

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	pcap_obj_t *obj = bf->o->bin_obj;
	pcap_hdr_t *header = obj->header;
	ret->file = strdup (bf->file);
	ret->type = r_str_newf ("tcpdump capture file - version %d.%d (%s, "
	  "capture length %"PFMT32u ")",
	header->version_major, header->version_minor,
	pcap_network_string (header->network), header->max_pkt_len);
	ret->rclass = strdup ("pcap");
	return ret;
}

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);

	switch (r_buf_read_be32_at (b, 0)) {
	case PCAP_MAGIC_LE:
	case PCAP_MAGIC_BE:
	case PCAP_NSEC_MAGIC_LE:
	case PCAP_NSEC_MAGIC_BE:
		return true;
		break;
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && bin_obj && buf, false);

	pcap_obj_t *obj = pcap_obj_new_buf (buf);
	if (obj) {
		*bin_obj = obj;
		return true;
	}
	return false;
}

static RList *symbols(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);

	RBinSymbol *ptr;
	pcap_obj_t *obj = bf->o->bin_obj;
	ut64 size = r_buf_size (obj->b);
	if (size == 0 || size == UT64_MAX) {
		return NULL;
	}
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	// File header
	ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		r_list_free (ret);
		return NULL;
	}
	ptr->name = r_str_newf ("tcpdump capture file - version %d.%d (%s, "
	  "capture length %"PFMT32u ")", obj->header->version_major,
	obj->header->version_minor, pcap_network_string (obj->header->network),
	obj->header->max_pkt_len);
	ptr->paddr = ptr->vaddr = 0;
	r_list_append (ret, ptr);

	// Go through each record packet
	RListIter *iter;
	pcaprec_t *rec;
	switch (obj->header->network) {
	case LINK_ETHERNET:
		r_list_foreach (obj->recs, iter, rec) {
			pcaprec_ether_sym_add (ret, rec, rec->paddr + sizeof (pcaprec_hdr_t));
		}
		break;
	default:
		break;
	}
	return ret;
}

static RList *strings(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);

	RBinString *ptr;
	pcap_obj_t *obj = bf->o->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RListIter *iter;
	pcaprec_t *rec;
	r_list_foreach (obj->recs, iter, rec) {
		if (rec->data && *rec->data != 0) {
			ptr = R_NEW0 (RBinString);
			if (!ptr) {
				r_list_free (ret);
				return NULL;
			}
			ptr->string = strdup ((char *)rec->data);
			ptr->paddr = ptr->vaddr = //XXX;
			ptr->length = strlen (ptr->string);
			ptr->size = ptr->length + 1;
			ptr->type = R_STRING_TYPE_DETECT;
			r_list_append (ret, ptr);
		}

	}
	return ret;
}

RBinPlugin r_bin_plugin_pcap = {
	.name = "pcap",
	.desc = "libpcap .pcap format r2 plugin",
	.license = "LGPL3",
	.info = info,
	.strings = strings,
	.symbols = symbols,
	.load_buffer= load_buffer,
	.check_buffer = check_buffer,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pcap,
	.version = R2_VERSION,
	.pkgname = "pcap"
};
#endif
