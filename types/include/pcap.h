#ifndef _PCAP_H_
#define _PCAP_H_

// Definitions
enum pcap_const {
	PCAP_MAGIC      = 0xa1b2c3d4, // Magic number for pcap files
	PCAP_NSEC_MAGIC = 0xa1b23c4d, // Modified pcap with nsec resolution
	LIBPCAP_MAGIC   = 0xa1b2cd34  // "libpcap" with Alexey Kuznetsoc's patches
};

// The network field in the pcap file header
typedef enum pcap_net {
	NOLINK = 0,
	ETHERNET = 1,
	ETHERNET_3MB = 2,
	AX_25 = 3,
	PRONET = 4,
	CHAOS = 5,
	TOKEN_RING = 6,
	ARCNET = 7,
	SLIP = 8,
	PPP = 9,
	FDDI = 10,
	RFC_1483_ATM_1 = 11,
	RAW_IP_1 = 12,
	BSDOS_SLIP_1 = 13,
	BSDOS_PPP_1 = 14,
	LINUX_ATM_CLASSICAL_IP = 19,
	PPP_CISCO_HDLC = 50,
	PPP_OVER_ETHERNET = 51,
	SYMANTEC_FIREWALL = 99,
	RFC_1483_ATM_2 = 100,
	RAW_IP_2 = 101,
	BSDOS_SLIP_2 = 102,
	BSDOS_PPP_2 = 103,
	BSDOS_CISCO_HDLC = 104,
	_802_11 = 105,
	LINUX_CLASSICAL_IP_ATM = 106,
	FRAME_RELAY = 107,
	OPENBSD_LOOPBACK = 108,
	OPENBSD_IPSEC_ENC = 109,
	CISCO_HDLC = 112,
	LINUX_COOKED = 113,
	LOCALTALK = 114,
	OPENBSD_PFLOG = 117,
	_802_11_PRISM = 119,
	RFC_2625_IP_FIBRE_CHANNEL = 122,
	SUNATM = 123,
	_802_11_RADIOTAP = 127,
	LINUX_ARCNET = 129,
	APPLE_IP_IEEE_1394 = 138,
	MTP2 = 140,
	MTP3 = 141,
	DOCSIS = 143,
	IRDA = 144,
	_802_11_AVS_HDR = 163,
} pcap_net_t;

// pcap file header
typedef struct pcap_file_hdr {
	uint32_t magic;			// magic number
	uint16_t version_major;
	uint16_t version_minor;
	int this_zone;		// GMT to local correction
	uint32_t ts_accuracy;	// Accuracy of timestamps
	uint32_t max_pkt_len;	// Max length of captured packets in bytes
	pcap_net_t network;	// Data link type
} pcap_file_hdr_t;

// Packet record header, always 16 bytes
typedef struct pcak_pktrec_hdr {
	uint32_t ts_sec;	// Timestamp in seconds
	uint32_t ts_usec;	// Timestamp in usec (nanosec for PCAP_NSEC_MAGIC)
	uint32_t cap_len;	// Length of packet captured
	uint32_t orig_len;	// Original length of packet
} pcap_pktrec_hdr_t;

// Ethernet header, always 14 bytes
typedef struct pcap_pktrec_ether {
	uint8_t  dst[6];	// Destination MAC address
	uint8_t  src[6];	// Source MAC address
	uint16_t type;	// 0x0080 = IPV4, 0xdd86 = IPV6 etc
} pcap_pktrec_ether_t;

// IPV4 header, atleast 20 bytes
typedef struct pcap_pktrec_ipv4 {
	uint8_t  ver_len;	// Upper nibble = version, lower = header len in 4-byte words
	uint8_t  diff_serv;	// Differentiated services field
	uint16_t tot_len;	// Total length of IPV4 packet
	uint16_t id;
	uint16_t flag_frag;	// Upper 3 bits = flags, lower 13 = fragment offset
	uint8_t  ttl;
	uint8_t  protocol;	// 6 = TCP
	uint16_t chksum;
	uint32_t src;		// Source IP
	uint32_t dst;		// Destination IP
} pcap_pktrec_ipv4_t;

// IPV6 header
typedef struct pcap_pktrec_ipv6 {
	uint32_t vc_flow;   // version, class, flow
	uint16_t plen;      // payload length
	uint8_t  nxt;       // next header
	uint8_t  hlim;      // hop limit
	uint8_t  src[16];   // source address
	uint8_t  dest[16];  // destination address
} pcap_pktrec_ipv6_t;

// TCP header, 20 - 60 bytes
typedef struct pcap_pktrec_tcp {
	uint16_t src_port;	// Port on source
	uint16_t dst_port;	// Port on destination
	uint32_t seq_num;	// Sequence number
	uint32_t ack_num;	// Ack number
	uint8_t  hdr_len;	// Length of TCP header
	uint16_t flags;		// TCP flags
	uint16_t win_sz;	// Window size
	uint16_t chksum;
	uint16_t urgnt_ptr;	// Urgent
	// Variable length options. Use hdr_len
} pcap_pktrec_tcp_t;


void read_pcap_file_hdr(pcap_file_hdr_t *hdr, const uint8_t *buf, int swap_endian);
void read_pcap_pktrec_hdr(pcap_pktrec_hdr_t *hdr, const uint8_t *buf, int swap_endian);
void read_pcap_pktrec_ether(pcap_pktrec_ether_t *hdr, const uint8_t *buf, int swap_endian);
void read_pcap_pktrec_ipv4(pcap_pktrec_ipv4_t *hdr, const uint8_t *buf, int swap_endian);
void read_pcap_pktrec_ipv6(pcap_pktrec_ipv6_t *hdr, const uint8_t *buf, int swap_endian);
void read_pcap_pktrec_tcp(pcap_pktrec_tcp_t *hdr, const uint8_t *buf, int swap_endian);

const char* pcap_net_type (uint32_t net);

#endif  // _PCAP_H_
