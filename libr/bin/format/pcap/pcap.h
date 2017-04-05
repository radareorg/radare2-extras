#include <r_util.h>

#ifndef _PCAP_H_
#define _PCAP_H_

// Definitions

#define PCAP_MAGIC      0xa1b2c3d4 // Magic number for pcap files
#define PCAP_NSEC_MAGIC 0xa1b23c4d // Modified pcap with nsec resolution

// Structures

// pcap file header
typedef struct pcap_file_hdr {
	ut32 magic;			// magic number
	ut16 version_major;
	ut16 version_minor;
	int this_zone;		// GMT to local correction
	ut32 ts_accuracy;	// Accuracy of timestamps
	ut32 max_pkt_len;	// Max length of captured packets in bytes
	ut32 network;		// Data link type
} pcap_file_hdr_t;

// Packet record header, always 16 bytes
typedef struct pcak_pktrec_hdr {
	ut32 ts_sec;	// Timestamp in seconds
	ut32 ts_usec;	// Timestamp in usec (nanosec for PCAP_NSEC_MAGIC)
	ut32 cap_len;	// Length of packet captured
	ut32 orig_len;	// Original length of packet
} pcap_pktrec_hdr_t;

// Ethernet header, always 14 bytes
typedef struct pcap_pktrec_ether {
	ut8  dst[6];	// Destination MAC address
	ut8  src[6];	// Source MAC address
	ut16 type;		// 0x0080 = IPV4, etc
} pcap_pktrec_ether_t;

// IPV4 header, always 20 bytes
typedef struct pcap_pktrec_ipv4 {
	ut8  ver_len;	// Upper nibble = version, lower = header len in 4-byte words
	ut8  diff_serv;	// Differentiated services field
	ut16 tot_len;	// Total length of IPV4 packet
	ut16 id;
	ut16 flag_frag;	// Upper 3 bits = flags, lower 13 = fragment offset
	ut8  ttl;
	ut8  protocol;	// 6 = TCP
	ut16 chksum;
	ut32 src;		// Source IP
	ut32 dst;		// Destination IP
} pcap_pktrec_ipv4_t;

// TCP header, 20 - 60 bytes
typedef struct pcap_pktrec_tcp {
	ut16 src_port;	// Port on source
	ut16 dst_port;	// Port on destination
	ut32 seq_num;	// Sequence number
	ut32 ack_num;	// Ack number
	ut8  hdr_len;	// Length of TCP header
	ut16 flags;		// TCP flags
	ut16 win_sz;	// Window size
	ut16 chksum;
	ut16 urgnt_ptr;	// Urgent
	// Variable length options. Use hdr_len
} pcap_pktrec_tcp_t;


#endif  // _PCAP_H_
