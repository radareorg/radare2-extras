/* Copyright (c) 1991, 1997 by Apple Computer, Inc.
 *
 * File: services/kdp.h
 *
 * Definition of remote debugger protocol.
 *
 * HISTORY
 * July 2001    Derek Kumar 
 *              Added KDP_REATTACH, KDP_BREAKPOINT_SET, KDP_BREAKPOINT_REMOVE
 *              packet definitions.
 * 17-Aug-1997  Klee Dienes  (klee@mit.edu)
 * 27-Oct-1991  Mike DeMoney (mike@next.com)
 * Created
 */

#ifndef _KDB_DEBUG_PROTOCOL_H_
#define _KDB_DEBUG_PROTOCOL_H_

#define KDP_MAX_PACKET_SIZE 1200 /* max packet size */
#define KDP_MAX_DATA_SIZE 1024	/* max r/w data per packet */

/* Requests */

typedef enum kdp_req_t {

 /* connection oriented requests */
 KDP_CONNECT, KDP_DISCONNECT,

 /* obtaining client info */
 KDP_HOSTINFO, KDP_VERSION, KDP_MAXBYTES,
 
 /* memory access */
 KDP_READMEM, KDP_WRITEMEM,
 
 /* register access */
 KDP_READREGS, KDP_WRITEREGS,
 
 /* executable image info */
 KDP_LOAD, KDP_IMAGEPATH,

 /* execution control */
 KDP_SUSPEND, KDP_RESUMECPUS,

 /* exception and termination notification, NOT true requests */
 KDP_EXCEPTION, KDP_TERMINATION,

 /* breakpoint control */
 KDP_BREAKPOINT_SET, KDP_BREAKPOINT_REMOVE,

 /* vm regions */
 KDP_REGIONS,

 /* reattach to a connected host */
 KDP_REATTACH
} kdp_req_t;

/* Common KDP packet header */

typedef struct {
  kdp_req_t request;		/* request type */
  unsigned char is_reply;	/* 0 => request, 1 => reply */
  unsigned char seq;		/* sequence number within session */
  unsigned int key;		/* session key */
} kdp_hdr_t;

/* KDP errors */

typedef enum {
  KDP_PROTERR_SUCCESS = 0,
  KDP_PROTERR_ALREADY_CONNECTED,
  KDP_PROTERR_BAD_NBYTES,
  KDP_PROTERR_BADFLAVOR,		/* bad flavor in w/r regs */
} kdp_error_t;

/* KDP requests and reply packet formats */

/* KDP_CONNECT */

typedef struct {
  kdp_hdr_t hdr;
  unsigned short req_reply_port; /* udp port which to send replies */
  unsigned short exc_note_port;  /* udp port which to send exc notes */
  char greeting[0];		 /* "greetings", null-terminated */
} kdp_connect_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_connect_reply_t;

/* KDP_DISCONNECT */

typedef struct {
  kdp_hdr_t hdr;
} kdp_disconnect_req_t;

typedef struct {
  kdp_hdr_t hdr;
} kdp_disconnect_reply_t;

typedef struct {
  kdp_hdr_t hdr;
  unsigned short req_reply_port; /* udp port which to send replies */
} kdp_reattach_req_t;

/* KDP_HOSTINFO */

typedef struct {
  kdp_hdr_t hdr;
} kdp_hostinfo_req_t;

typedef struct {
  kdp_hdr_t hdr;
  unsigned int cpu_mask;
  unsigned int cpu_type;
  unsigned int cpu_subtype;
} kdp_hostinfo_reply_t;

/*
 * KDP_VERSION
 */
typedef struct {
  kdp_hdr_t  hdr;
} kdp_version_req_t;

#define	KDP_FEATURE_BP	0x1     /* local breakpoint support */

typedef struct {
  kdp_hdr_t  hdr;
  unsigned   version;
  unsigned   feature;
  unsigned   pad0;
  unsigned   pad1;
} kdp_version_reply_t;

/* KDP_REGIONS */

typedef struct {
  kdp_hdr_t hdr;
} kdp_regions_req_t;

typedef struct {
  kdp_hdr_t hdr;
  unsigned nregions;
  struct {
    unsigned long address;
    size_t nbytes;
    unsigned int protection;
  } regions[0];
} kdp_regions_reply_t;

/* KDP_MAXBYTES */

typedef struct {
  kdp_hdr_t hdr;
} kdp_maxbytes_req_t;

typedef struct {
  kdp_hdr_t hdr;
  size_t max_bytes;
} kdp_maxbytes_reply_t;

/* KDP_READMEM */

typedef struct {
  kdp_hdr_t hdr;
  unsigned long address;
  size_t nbytes;
} kdp_readmem_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
  size_t nbytes;
  unsigned char data[0];
} kdp_readmem_reply_t;

/* KDP_WRITEMEM */

typedef struct {
  kdp_hdr_t hdr;
  unsigned long address;
  size_t nbytes;
  unsigned char data[0];
} kdp_writemem_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_writemem_reply_t;

/* KDP_READREGS */

typedef struct {
  kdp_hdr_t hdr;
  unsigned int cpu;
  unsigned int flavor;
} kdp_readregs_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
  size_t nbytes;
  unsigned char data[0];
} kdp_readregs_reply_t;

/* KDP_WRITEREGS */

typedef struct {
  kdp_hdr_t hdr;
  unsigned int cpu;
  unsigned int flavor;
  size_t nbytes;
  unsigned char data[0];
} kdp_writeregs_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_writeregs_reply_t;

/* KDP_LOAD */

typedef struct {
  kdp_hdr_t hdr;
  char file_args[0];
} kdp_load_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_load_reply_t;

/* KDP_IMAGEPATH */

typedef struct {
  kdp_hdr_t hdr;
} kdp_imagepath_req_t;

typedef struct {
  kdp_hdr_t hdr;
  char path[0];
} kdp_imagepath_reply_t;

/* KDP_SUSPEND */

typedef struct {
  kdp_hdr_t hdr;
} kdp_suspend_req_t;

typedef struct {
  kdp_hdr_t hdr;
} kdp_suspend_reply_t;

/* KDP_RESUMECPUS */

typedef struct {
  kdp_hdr_t hdr;
  unsigned int cpu_mask;
} kdp_resumecpus_req_t;

typedef struct {
  kdp_hdr_t hdr;
} kdp_resumecpus_reply_t;

/* KDP_BREAKPOINT_SET, KDP_BREAKPOINT_REMOVE */
typedef struct {
  kdp_hdr_t hdr;
  unsigned long address;
#if 0
  unsigned long ccache;
#endif
} kdp_breakpoint_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_breakpoint_reply_t;

/* Exception notifications */

/* (Exception notifications are not requests, and in fact travel from
   the remote debugger to the gdb agent KDB.) */

/* exc. info for one cpu */

typedef struct kdp_exc_info_t {
  unsigned int cpu;
  unsigned int exception;
  unsigned int code;
  unsigned int subcode;
} kdp_exc_info_t;

typedef struct kdp_exception_t {
  kdp_hdr_t hdr;
  size_t n_exc_info;
  kdp_exc_info_t exc_info[0];
} kdp_exception_t;

typedef struct kdp_exception_ack_t {
  kdp_hdr_t hdr;
} kdp_exception_ack_t;

/* Child termination messages */

typedef enum kdp_termination_code_t {
  KDP_FAULT = 0,		/* child took fault (internal use) */
  KDP_EXIT,			/* child exited */
  KDP_POWEROFF,			/* child power-off */
  KDP_REBOOT,			/* child reboot */
  KDP_COMMAND_MODE,		/* child exit to mon command_mode */
} kdp_termination_code_t;

typedef struct kdp_termination_t {
  kdp_hdr_t hdr;
  kdp_termination_code_t term_code;
  unsigned int exit_code;
} kdp_termination_t;

typedef struct kdp_termination_ack_t {
  kdp_hdr_t hdr;
} kdp_termination_ack_t;

typedef union kdp_pkt_t {
  kdp_hdr_t hdr;
  kdp_connect_req_t connect_req;
  kdp_connect_reply_t connect_reply;
  kdp_disconnect_req_t disconnect_req;
  kdp_disconnect_reply_t disconnect_reply;
  kdp_hostinfo_req_t hostinfo_req;
  kdp_hostinfo_reply_t hostinfo_reply;
  kdp_version_req_t version_req;
  kdp_version_reply_t version_reply;
  kdp_maxbytes_req_t maxbytes_req;
  kdp_maxbytes_reply_t maxbytes_reply;
  kdp_readmem_req_t readmem_req;
  kdp_readmem_reply_t readmem_reply;
  kdp_writemem_req_t writemem_req;
  kdp_writemem_reply_t writemem_reply;
  kdp_readregs_req_t readregs_req;
  kdp_readregs_reply_t readregs_reply;
  kdp_writeregs_req_t writeregs_req;
  kdp_writeregs_reply_t writeregs_reply;
  kdp_load_req_t  load_req;
  kdp_load_reply_t load_reply;
  kdp_imagepath_req_t imagepath_req;
  kdp_imagepath_reply_t imagepath_reply;
  kdp_suspend_req_t suspend_req;
  kdp_suspend_reply_t suspend_reply;
  kdp_resumecpus_req_t resumecpus_req;
  kdp_resumecpus_reply_t resumecpus_reply;
  kdp_exception_t  exception;
  kdp_exception_ack_t exception_ack;
  kdp_termination_t termination;
  kdp_termination_ack_t termination_ack;
  kdp_breakpoint_req_t breakpoint_req;
  kdp_breakpoint_reply_t breakpoint_reply;
  kdp_regions_req_t regions_req;
  kdp_regions_reply_t regions_reply;
  kdp_reattach_req_t reattach_req;
} kdp_pkt_t;

typedef enum {
  KDP_LOG_ERROR = 1,
  KDP_LOG_WARNING = 2,
  KDP_LOG_INFO = 3,
  KDP_LOG_DEBUG = 4
} kdp_log_level;

typedef enum {
  RR_SUCCESS = 0,
  RR_ALREADY_CONNECTED = KDP_PROTERR_ALREADY_CONNECTED,
  RR_BAD_NBYTES = KDP_PROTERR_BAD_NBYTES,
  RR_BADFLAVOR = KDP_PROTERR_BADFLAVOR,
  RR_SEND_TIMEOUT,
  RR_RECV_TIMEOUT,
  RR_IP_ERROR,			/* misc. network error */
  RR_BAD_ACK,			/* bad packet_type on ack */
  RR_BYTE_COUNT,		/* unexpected byte count */
  RR_BAD_SEQ,			/* unexpected sequence number */
  RR_RESOURCE,			/* resource shortage */
  RR_LOOKUP,			/* can't find target */ 
  RR_INTERNAL,			/* internal error */
  RR_CONNECT,			/* connection failure */
  RR_INVALID_ADDRESS,		/* bad memory address */
  RR_EXCEPTION,			/* exception is new */
  RR_RECV_INTR,
} kdp_return_t;

typedef void (kdp_log_function) (kdp_log_level l, const char *s, ...);

const char *kdp_req_string (kdp_req_t req);
const char *kdp_error_string (kdp_error_t error);
const char *kdp_return_string (kdp_return_t error);

struct kdp_connection;

void kdp_log_data
  (kdp_log_function *f, kdp_log_level l, const unsigned char *data, unsigned int nbytes);

void kdp_log_packet
  (kdp_log_function *f, kdp_log_level l, const kdp_pkt_t *p);

kdp_return_t kdp_marshal
  (struct kdp_connection *c, kdp_pkt_t *p, unsigned char *s, size_t maxlen, size_t *plen);

kdp_return_t kdp_unmarshal
  (struct kdp_connection *c, kdp_pkt_t *p, const unsigned char *s, size_t rlen);

#endif /* _KDB_DEBUG_PROTOCOL_H_ */
