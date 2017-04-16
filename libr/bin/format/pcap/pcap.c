#include "pcap.h"

void read_pcap_file_hdr(pcap_file_hdr_t *hdr, const ut8 *buf, int swap_endian) {
	memcpy (hdr, buf, sizeof (pcap_file_hdr_t));
	if (swap_endian) {
		hdr->magic = r_swap_ut32 (hdr->magic);
		hdr->version_major = r_swap_ut16 (hdr->version_major);
		hdr->version_minor = r_swap_ut16 (hdr->version_minor);
		hdr->this_zone = r_swap_st32 (hdr->this_zone);
		hdr->ts_accuracy = r_swap_ut32 (hdr->ts_accuracy);
		hdr->max_pkt_len = r_swap_ut32 (hdr->max_pkt_len);
		hdr->network = r_swap_ut32 (hdr->network);
	}
}

void read_pcap_pktrec_hdr(pcap_pktrec_hdr_t *hdr, const ut8 *buf, int swap_endian) {
	memcpy (hdr, buf, sizeof (pcap_pktrec_hdr_t));
	if (swap_endian) {
		hdr->ts_sec = r_swap_ut32 (hdr->ts_sec);
		hdr->ts_usec = r_swap_ut32 (hdr->ts_usec);
		hdr->cap_len = r_swap_ut32 (hdr->cap_len);
		hdr->orig_len = r_swap_ut32 (hdr->orig_len);
	}
}

void read_pcap_pktrec_ether(pcap_pktrec_ether_t *hdr, const ut8 *buf, int swap_endian) {
	memcpy (hdr, buf, sizeof (pcap_pktrec_ether_t));
	if (swap_endian) {
		hdr->type = r_swap_ut16 (hdr->type);
	}
}

void read_pcap_pktrec_ipv4(pcap_pktrec_ipv4_t *hdr, const ut8 *buf, int swap_endian) {
	memcpy (hdr, buf, sizeof (pcap_pktrec_ipv4_t));
	hdr->tot_len = r_read_be16 (&hdr->tot_len);
	hdr->src = r_read_be32 (&hdr->src);
	hdr->dst = r_read_be32 (&hdr->dst);
	hdr->id = r_read_be16 (&hdr->id);
	hdr->flag_frag = r_read_be16 (&hdr->flag_frag);
	hdr->chksum = r_read_be16 (&hdr->chksum);
}

void read_pcap_pktrec_tcp(pcap_pktrec_tcp_t *hdr, const ut8 *buf, int swap_endian) {
	memcpy (hdr, buf, sizeof (pcap_pktrec_tcp_t));
	if (swap_endian) {
		hdr->src_port = r_swap_ut16 (hdr->src_port);
		hdr->dst_port = r_swap_ut16 (hdr->dst_port);
		hdr->seq_num = r_swap_ut32 (hdr->seq_num);
		hdr->ack_num = r_swap_ut32 (hdr->ack_num);
		hdr->flags = r_swap_ut16 (hdr->flags);
		hdr->win_sz = r_swap_ut16 (hdr->win_sz);
		hdr->chksum = r_swap_ut16 (hdr->chksum);
		hdr->urgnt_ptr = r_swap_ut16 (hdr->urgnt_ptr);
	}
}

const char* pcap_net_type(ut32 net) {
	switch (net) {
	case NOLINK:
		return "No link-layer encapsulation";
	case ETHERNET:
		return "Ethernet";
	case ETHERNET_3MB:
		return "3Mb Ethernet";
	case AX_25:
		return "AX.25";
	case PRONET:
		return "ProNET";
	case CHAOS:
		return "CHAOS";
	case TOKEN_RING:
		return "Token Ring";
	case ARCNET:
		return "ARCNET";
	case SLIP:
		return "SLIP";
	case PPP:
		return "PPP";
	case FDDI:
		return "FDDI";
	case RFC_1483_ATM_1:
	case RFC_1483_ATM_2:
		return "RFC 1483 ATM";
	case RAW_IP_1:
	case RAW_IP_2:
		return "raw IP";
	case BSDOS_SLIP_1:
	case BSDOS_SLIP_2:
		return "BSD/OS SLIP";
	case BSDOS_PPP_1:
	case BSDOS_PPP_2:
		return "BSD/OS PPP";
	case LINUX_ATM_CLASSICAL_IP:
		return "Linux ATM Classical IP";
	case PPP_CISCO_HDLC:
		return "PPP or Cisco HDLC";
	case PPP_OVER_ETHERNET:
		return "PPP-over-Ethernet";
	case SYMANTEC_FIREWALL:
		return "Symantec Enterprise Firewall";
	case BSDOS_CISCO_HDLC:
		return "BSD/OS Cisco HDLC";
	case _802_11:
		return "802.11";
	case LINUX_CLASSICAL_IP_ATM:
		return "Linux Classical IP over ATM";
	case FRAME_RELAY:
		return "Frame Relay";
	case OPENBSD_LOOPBACK:
		return "OpenBSD loopback";
	case OPENBSD_IPSEC_ENC:
		return "OpenBSD IPsec encrypted";
	case CISCO_HDLC:
		return "Cisco HDLC";
	case LINUX_COOKED:
		return "Linux \"cooked\"";
	case LOCALTALK:
		return "LocalTalk";
	case OPENBSD_PFLOG:
		return "OpenBSD PFLOG";
	case _802_11_PRISM:
		return "802.11 with Prism header";
	case RFC_2625_IP_FIBRE_CHANNEL:
		return "RFC 2625 over Fibre Channel";
	case SUNATM:
		return "SunATM";
	case _802_11_RADIOTAP:
		return "802.11 with radiotap header";
	case LINUX_ARCNET:
		return "Linux ARCNET";
	case APPLE_IP_IEEE_1394:
		return "Apple IP over IEEE 1394";
	case MTP2:
		return "MTP2";
	case MTP3:
		return "MTP3";
	case DOCSIS:
		return "DOCSIS";
	case IRDA:
		return "IrDA";
	case _802_11_AVS_HDR:
		return "802.11 with AVS header";
	default:
		return "Unkown";
	}
}
