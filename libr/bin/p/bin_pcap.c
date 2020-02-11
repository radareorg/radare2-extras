#include <r_bin.h>
#include <r_lib.h>
#include <r_types.h>
#include "pcap.h"

#define OPP_ENDIAN  1
#define SAME_ENDIAN 0

// The pcap object for RBinFile
typedef struct pcap_obj {
	struct pcap_file_hdr header;	// File header
	bool is_nsec;					// nsec timestamp resolution?
	int endian;	// Relative endianness (same or different from host)
} pcap_obj_t;


// Functions

static RBinInfo *info(RBinFile *arch) {
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	pcap_file_hdr_t *header = &((pcap_obj_t *) arch->o->bin_obj)->header;
	ret->file = strdup (arch->file);
	ret->type = r_str_newf ("tcpdump capture file - version %d.%d (%s, "
		"capture length %"PFMT32u ")", header->version_major,
		header->version_minor, pcap_net_type (header->network),
		header->max_pkt_len);
	ret->rclass = strdup ("pcap");
	return ret;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < sizeof (pcap_file_hdr_t) || length == UT64_MAX) {
		return false;
	}
	pcap_file_hdr_t *header = (pcap_file_hdr_t *) buf;
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

static bool check_buffer(RBuffer *b) {
	ut8 buf[1024];
	r_buf_read_at (b, 0, buf, sizeof (buf));
	return check_bytes (buf, sizeof (buf));
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
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
	// Reload file header
	read_pcap_file_hdr (&obj->header, buf, obj->endian);
	return obj;
}

static void _read_tcp_sym(RList *list, const ut8 *buf, ut64 off, ut64 sz, ut64 tcplen, int endian) {
	RBinSymbol *ptr = NULL;
	if (off + sizeof (pcap_pktrec_tcp_t) > sz) {
		return;
	}
	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return;
	}
	pcap_pktrec_tcp_t tcp;
	read_pcap_pktrec_tcp (&tcp, &buf[off], endian);
	ut64 tcp_data_len = tcplen - (((tcp.hdr_len >> 4) & 0x0F) * 4);
	ptr->name = r_str_newf ("0x%x: Transmission Control Protocol, Src Port: %d, Dst"
		" port: %d, Len: %d", off, tcp.src_port, tcp.dst_port,
		tcp_data_len);
	ptr->paddr = ptr->vaddr = off;
	r_list_append (list, ptr);
}

static void _read_ipv4_sym(RList *list, const ut8 *buf, ut64 off, ut64 sz, int endian) {
	RBinSymbol *ptr = NULL;
	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return;
	}
	pcap_pktrec_ipv4_t ipv4;
	read_pcap_pktrec_ipv4 (&ipv4, &buf[off], endian);
	ptr->name = r_str_newf ("0x%"PFMT64x": IPV%d, Src: %d.%d.%d.%d, Dst: %d.%d.%d.%d",
		off, (ipv4.ver_len >> 4) & 0x0F, (ipv4.src >> 24) & 0xFF,
		(ipv4.src >> 16) & 0xFF, (ipv4.src >> 8) & 0xFF,
		ipv4.src & 0xFF, (ipv4.dst >> 24) & 0xFF,
		(ipv4.dst >> 16) & 0xFF, (ipv4.dst >> 8) & 0xFF,
		ipv4.dst & 0xFF);
	ptr->paddr = ptr->vaddr = off;
	r_list_append (list, ptr);
	if (off + ipv4.tot_len > sz) {
		return;
	}
	off += (ipv4.ver_len & 0x0F) * 4;

	// For now, if not TCP, continue. TODO others
	switch (ipv4.protocol) {
	case 6:
		_read_tcp_sym (list, buf, off, sz, (ipv4.tot_len - ((ipv4.ver_len & 0x0F) * 4)), endian);
	}
}

static void _write_ipv6_addr(const ut8 *addr, char *buf, int len) {
	struct { int start, len; } best, cur;
	ut16 words[8] = { 0 };
	int i;
	char *ptr = buf;
	best.start = cur.start = -1;
	best.len = cur.len = 0;
	for (i = 0; i < 8; i++) {
		words[i] = (addr[i * 2] << 4) | addr[i * 2 + 1];
		if (words[i] == 0) {
			if (cur.start == -1) {
				cur.start = i;
				cur.len = 1;
			} else {
				cur.len++;
			}
			continue;
		}
		if (cur.start != -1) {
			if (best.start == -1 || cur.len > best.len) {
				best.start = cur.start;
				best.len = cur.len;
			}
			cur.start = -1;
		}
	}
	if (best.start == -1 || cur.len > best.len) {
		best.start = cur.start;
		best.len = cur.len;
	}
	if (best.len < 2) {
		best.start = -1;
	}
	for (i = 0; i < 8; i++) {
		if (i == best.start) {
			*ptr++ = ':';
			continue;
		}
		if (best.start != -1 && i > best.start && i < best.start + best.len) {
			continue;
		}
		if (i != 0) {
			*ptr++ = ':';
		}
		ptr += snprintf (ptr, len - (ptr - buf), "%x", words[i]);
	}
}

static void _read_ipv6_sym(RList *list, const ut8 *buf, ut64 off, ut64 sz, int endian) {
	RBinSymbol *ptr = NULL;
	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return;
	}
	char write_buf[256] = { 0 };
	pcap_pktrec_ipv6_t ipv6;
	int len;
	read_pcap_pktrec_ipv6 (&ipv6, &buf[off], endian);
	snprintf (write_buf, sizeof (write_buf) - 1, "0x%"PFMT64x": IPV6, Src: ", off);
	len = strlen (write_buf);
	_write_ipv6_addr (ipv6.src, write_buf + len, sizeof (write_buf) - len);
	len += strlen (write_buf + len);
	strcpy (write_buf + len, ", Dst: ");
	len += strlen (write_buf + len);
	_write_ipv6_addr (ipv6.dest, write_buf + len, sizeof (write_buf) - len);

	if (!(ptr->name = strdup (write_buf))) {
		free (ptr);
		return;
	}
	ptr->paddr = ptr->vaddr = off;
	r_list_append (list, ptr);
	if (off + ipv6.plen + sizeof (pcap_pktrec_ipv6_t) > sz) {
		return;
	}
	off += sizeof (pcap_pktrec_ipv6_t);

	// For now, if not TCP, continue. TODO others
	switch (ipv6.nxt) {
	case 6:
		_read_tcp_sym (list, buf, off, sz, ipv6.plen, endian);
	}
}

static void _read_ether_sym(RList *list, const ut8 *buf, ut64 off, ut64 sz, int endian) {
	RBinSymbol *ptr = NULL;
	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return;
	}
	pcap_pktrec_ether_t ether;
	read_pcap_pktrec_ether (&ether, &buf[off], endian);
	ptr->name = r_str_newf ("0x%x: Ethernet, Src: %02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x
		":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x ", Dst: %02"PFMT32x
		":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x ":%02"PFMT32x
		":%02"PFMT32x, off, ether.src[0], ether.src[1],
		ether.src[2], ether.src[3], ether.src[4], ether.src[5],
		ether.dst[0], ether.dst[1], ether.dst[2], ether.dst[3],
		ether.dst[4], ether.dst[5]);
	ptr->paddr = ptr->vaddr = off;
	r_list_append (list, ptr);
	off += sizeof (pcap_pktrec_ether_t);

	// For now, if not IPV4, continue. TODO IPV6
	switch (ether.type) {
	case 0x08:
		_read_ipv4_sym (list, buf, off, sz, endian);
		break;
	case 0xdd86:
		_read_ipv6_sym (list, buf, off, sz, endian);
	}
}

static RList *symbols(RBinFile *arch) {
	RBinSymbol *ptr = NULL;
	RList *ret = NULL;
	pcap_obj_t *obj = NULL;
	ut64 sz = 0;
	ut64 off;
	ut64 pkt_num = 0;
	if (!arch || !arch->o || !arch->o->bin_obj || !arch->buf) {
		return NULL;
	}
	obj = arch->o->bin_obj;
	ut8 buf[1024]; // sizeof(pcap_file-hdr
	r_buf_read_at (arch->buf, 0, buf, sizeof (buf));
	sz = r_buf_size (arch->buf);
	if (sz == 0 || sz == UT64_MAX) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	// File header
	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return ret;
	}
	ptr->name = r_str_newf ("tcpdump capture file - version %d.%d (%s, "
		"capture length %"PFMT32u ")", obj->header.version_major,
		obj->header.version_minor, pcap_net_type (obj->header.network),
		obj->header.max_pkt_len);
	ptr->paddr = ptr->vaddr = 0;
	r_list_append (ret, ptr);

	// Go through each packet
	off = sizeof (pcap_file_hdr_t);
	while (off <= sz - sizeof (pcap_pktrec_hdr_t)) {
		pkt_num++;

		// Frame header
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			break;
		}
		pcap_pktrec_hdr_t pkthdr;
		read_pcap_pktrec_hdr (&pkthdr, &buf[off], obj->endian);
		ptr->name = r_str_newf ("0x%x: Frame %d, %d bytes on wire, %d bytes captured",
			off, pkt_num, pkthdr.orig_len, pkthdr.cap_len);
		ptr->paddr = ptr->vaddr = off;
		r_list_append (ret, ptr);

		// Check if rest of file is present. If not, break
		if (off + sizeof (pcap_pktrec_hdr_t) + pkthdr.cap_len > sz) {
			break;
		}

		// For now, if not ethernet, continue. TODO others
		switch (obj->header.network) {
		case ETHERNET:
			_read_ether_sym (ret, buf, off + sizeof (pcap_pktrec_hdr_t), sz, obj->endian);
		default:
			break;
		}
		off += sizeof (pcap_pktrec_hdr_t) + pkthdr.cap_len;
	}

	return ret;
}

static RList *strings(RBinFile *arch) {
	RBinString *ptr = NULL;
	RList *ret = NULL;
	pcap_obj_t *obj = NULL;
	char *tmp = NULL;
	ut64 sz = 0;
	ut64 off;
	if (!arch || !arch->o || !arch->o->bin_obj || !arch->buf) {
		return NULL;
	}
	obj = arch->o->bin_obj;
	ut8 buf[1024];
	r_buf_read_at (arch->buf, 0, buf, sizeof (buf));
	sz = r_buf_size (arch->buf);
	if (sz == 0 || sz == UT64_MAX) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(tmp = malloc (obj->header.max_pkt_len + 1))) {
		return ret;
	}

	// Go through each packet
	off = sizeof (pcap_file_hdr_t);
	while (off <= sz - sizeof (pcap_pktrec_hdr_t)) {
		ut64 tmp_off = off;
		// Frame header
		pcap_pktrec_hdr_t pkthdr;
		read_pcap_pktrec_hdr (&pkthdr, &buf[tmp_off], obj->endian);
		if (tmp_off + sizeof (pcap_pktrec_hdr_t) + pkthdr.cap_len > sz) {
			break;
		}
		off += sizeof (pcap_pktrec_hdr_t) + pkthdr.cap_len;

		// Ethernet data. For now, if not ethernet, continue. TODO others
		if (obj->header.network != ETHERNET) {
			continue;
		}
		tmp_off += sizeof (pcap_pktrec_hdr_t);
		pcap_pktrec_ether_t ether;
		read_pcap_pktrec_ether (&ether, &buf[tmp_off], obj->endian);

		// IPV4 data. For now, if not IPV4, continue. TODO IPV6
		if (ether.type != 0x08) {
			continue;
		}
		tmp_off += sizeof (pcap_pktrec_ether_t);
		pcap_pktrec_ipv4_t ipv4;
		read_pcap_pktrec_ipv4 (&ipv4, &buf[tmp_off], obj->endian);
		if (tmp_off + ipv4.tot_len > sz) {
			continue;
		}

		// TCP header data. For now, if not TCP, continue. TODO others}
		if (ipv4.protocol != 6) {
			continue;
		}
		tmp_off += (ipv4.ver_len & 0x0F) * 4;
		if (tmp_off + sizeof (pcap_pktrec_tcp_t) > sz) {
			continue;
		}
		pcap_pktrec_tcp_t tcp;
		read_pcap_pktrec_tcp (&tcp, &buf[tmp_off], obj->endian);
		ut64 tcp_data_len = (ipv4.tot_len - ((ipv4.ver_len & 0x0F) * 4)) -
				    (((tcp.hdr_len >> 4) & 0x0F) * 4);
		if (tcp_data_len <= 1) {
			continue;
		}
		tmp_off += ((tcp.hdr_len >> 4) & 0x0F) * 4;
		if (tcp_data_len > obj->header.max_pkt_len || tmp_off + tcp_data_len > sz) {
			continue;
		}
		size_t str_len;

		memset (tmp, 0, obj->header.max_pkt_len);
		strncpy (tmp, (const char *) &buf[tmp_off], tcp_data_len);
		tmp[tcp_data_len] = '\0';
		if (!(str_len = strlen (tmp))) {
			continue;
		}
		if (!(ptr = R_NEW0 (RBinString))) {
			break;
		}
		ptr->string = strdup (tmp);
		ptr->paddr = ptr->vaddr = tmp_off;
		ptr->length = str_len;
		ptr->size = ptr->length + 1;
		ptr->type = R_STRING_TYPE_DETECT;
		r_list_append (ret, ptr);

	}
	free (tmp);
	return ret;
}

static bool load(RBinFile *arch) {
	if (!arch || !arch->o) {
		return false;
	}
	ut64 size = r_buf_size (arch->buf);
	ut8 *bytes = malloc (size);
	if (!bytes || size == 0 || size == UT64_MAX) {
		return false;
	}
	r_buf_read_at (arch->buf, 0, bytes, size);
	arch->o->bin_obj = load_bytes (arch, bytes, size, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj != NULL;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return load(bf);
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
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pcap,
	.version = R2_VERSION,
};
#endif
