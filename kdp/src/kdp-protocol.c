#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "kdp-udp.h"

static inline unsigned short read16u (const unsigned char *s, int bigendian)
{
  if (bigendian) {
    return (s[1] << 8) + s[0];
  } else {
    return (s[0] << 8) + s[1];
  }
}

static inline unsigned long read32u (const unsigned char *s, int bigendian)
{
  if (bigendian) {
    return (s[3] << 24) + (s[2] << 16) + (s[1] << 8) + s[0];
  } else {
    return (s[0] << 24) + (s[1] << 16) + (s[2] << 8) + s[3];
  }
}

static inline void write16u (unsigned char *s, unsigned short i, int bigendian)
{
  if (bigendian) {
    s[1] = (i >> 8) & 0xff;
    s[0] = (i >> 0) & 0xff;
  } else {
    s[0] = (i >> 8) & 0xff;
    s[1] = (i >> 0) & 0xff;
  }
}

static inline void write32u (unsigned char *s, unsigned long i, int bigendian)
{
  if (bigendian) {
    s[3] = (i >> 24) & 0xff;
    s[2] = (i >> 16) & 0xff;
    s[1] = (i >> 8) & 0xff;
    s[0] = (i >> 0) & 0xff;
  } else {
    s[0] = (i >> 24) & 0xff;
    s[1] = (i >> 16) & 0xff;
    s[2] = (i >> 8) & 0xff;
    s[3] = (i >> 0) & 0xff;
  }
}

const char *kdp_req_string (kdp_req_t req)
{
  switch (req) {
    case KDP_CONNECT: return "CONNECT";
    case KDP_DISCONNECT: return "DISCONNECT";
    case KDP_HOSTINFO: return "HOSTINFO";
    case KDP_REGIONS: return "REGIONS";
    case KDP_MAXBYTES: return "MAXBYTES";
    case KDP_READMEM: return "READMEM";
    case KDP_WRITEMEM: return "WRITEMEM";
    case KDP_READREGS: return "READREGS";
    case KDP_WRITEREGS: return "WRITEREGS";
    case KDP_LOAD: return "LOAD";
    case KDP_IMAGEPATH: return "IMAGEPATH";
    case KDP_SUSPEND: return "SUSPEND";
    case KDP_RESUMECPUS: return "RESUMECPUS";
    case KDP_EXCEPTION: return "EXCEPTION";
    case KDP_TERMINATION: return "TERMINATION";
    default: return "[UNKNOWN]";
    }
}

const char *kdp_error_string (kdp_error_t error)
{
  switch (error) {
  case KDP_PROTERR_SUCCESS: return "no error detected";
  case KDP_PROTERR_ALREADY_CONNECTED: return "target already connected";
  case KDP_PROTERR_BAD_NBYTES: return "invalid memory access";
  case KDP_PROTERR_BADFLAVOR: return "bad thread state flavor";
  default: return "unknown error";
  }
}

const char *kdp_return_string (kdp_return_t error)
{
  switch (error) {
  case RR_SUCCESS: return "no error detected";
  case RR_ALREADY_CONNECTED: return "target already connected";
  case RR_BAD_NBYTES: return "illegal address or byte count";
  case RR_BADFLAVOR: return "bad thread state flavor";
  case RR_SEND_TIMEOUT: return "send timeout exceeded";
  case RR_RECV_TIMEOUT: return "receive timeout exceeded";
  case RR_IP_ERROR: return "RR_IP_ERROR";
  case RR_BAD_ACK: return "RR_BAD_ACK";
  case RR_BYTE_COUNT: return "RR_BYTE_COUNT";
  case RR_BAD_SEQ: return "RR_BAD_SEQ";
  case RR_RESOURCE: return "RR_RESOURCE";
  case RR_LOOKUP: return "RR_LOOKUP";
  case RR_INTERNAL: return "RR_INTERNAL";
  case RR_CONNECT: return "RR_CONNECT";
  case RR_INVALID_ADDRESS: return "RR_INVALID_ADDRESS";
  case RR_EXCEPTION: return "RR_EXCEPTION";
  case RR_RECV_INTR: return "RR_RECV_INTR";
  default: return "[UNKNOWN]";
  }
}

void kdp_log_data
(kdp_log_function *f, kdp_log_level l, const unsigned char *data, unsigned int nbytes)
{
  unsigned int i;
  for (i = 0; i < (nbytes / 4); i++) {
    const unsigned char *s = data + (i * 4);
    if (i == 0) {
      f (l, "  %8s:", "data");
    }
    f (l, " 0x%02x%02x%02x%02x", s[0], s[1], s[2], s[3]);
    if ((i % 6) == 5) {
      f (l, "\n           ");
    }
  }
  if (i == 0) {
    f (l, "  %8s:", "data");
  }
  for (i = i * 4; i < nbytes; i++) {
    f (l, " 0x%02x", data[i]);
  }
  f (l, "\n");
}

void kdp_log_packet
  (kdp_log_function *f, kdp_log_level l, const kdp_pkt_t *p) 
{
  const kdp_hdr_t *h = &p->hdr;
  unsigned int i;

  f (l,
     "{\n"
     "  %8s: %s\n"
     "  %8s: %d\n"
     "  %8s: %d\n"
     "  %8s: %d\n",
     "request", kdp_req_string (h->request),
     "is_reply", h->is_reply,
     "seq", h->seq,
     "key", h->key);

  if (h->is_reply) {

    switch (h->request) {
    case KDP_CONNECT:
      f (l, 
	 "  %8s: \"%s\" (%d)\n",
	 "error", kdp_error_string (p->connect_reply.error), p->connect_reply.error);
      break;
    case KDP_DISCONNECT:
      break;
    case KDP_HOSTINFO:
      f (l,
	 "  %8s: %d\n"
	 "  %8s: %d\n"
	 "  %8s: %d\n",
	 "cpu_mask", p->hostinfo_reply.cpu_mask,
	 "type", p->hostinfo_reply.cpu_type,
	 "subtype", p->hostinfo_reply.cpu_subtype);
      break;
    case KDP_REGIONS:
      f (l,
	 "  %8s: %d\n",
	 "nregions", p->regions_reply.nregions);
      for (i = 0; i < p->regions_reply.nregions; i++) {
	f (l,
	   "            r[%d].addr: %d\n"
	   "            r[%d].nbytes: %d\n"
	   "            r[%d].prot: %d\n",
	   i, p->regions_reply.regions[i].address,
	   i, p->regions_reply.regions[i].nbytes,
	   i, p->regions_reply.regions[i].protection);
      }
      break;
    case KDP_MAXBYTES:
      f (l,
	 "  %8s: %d\n",
	 "maxbytes", p->maxbytes_reply.max_bytes);
      break;
    case KDP_READMEM:
      f (l,
	 "  %8s: \"%s\" (%d)\n"
	 "  %8s: %d\n",
	 "error", kdp_error_string (p->readmem_reply.error), p->readmem_reply.error,
	 "nbytes", p->readmem_reply.nbytes);
      kdp_log_data (f, l, p->readmem_reply.data, p->readmem_reply.nbytes);
      break;
    case KDP_WRITEMEM:
      f (l,
	 "  %8s: \"%s\" (%d)\n",
	 "error", kdp_error_string (p->writemem_reply.error), p->writemem_reply.error);
      break;
    case KDP_READREGS:
      f (l,
	 "  %8s: \"%s\" (%d)\n"
	 "  %8s: %d\n",
	 "error", kdp_error_string (p->readregs_reply.error), p->readregs_reply.error,
	 "nbytes", p->readregs_reply.nbytes);
      kdp_log_data (f, l, p->readregs_reply.data, p->readregs_reply.nbytes);
      break;
    case KDP_WRITEREGS:
      f (l,
	 "  %8s: \"%s\" (%d)\n",
	 "error", kdp_error_string (p->writeregs_reply.error), p->writeregs_reply.error);
      break;
    case KDP_LOAD:
      f (l,
	 "  %8s: \"%s\" (%d)\n",
	 "error", kdp_error_string (p->load_reply.error), p->load_reply.error);
      break;
    case KDP_IMAGEPATH:
      f (l,
	 "  %8s: \"%s\"\n",
	 "path", p->imagepath_reply.path);
      break;
    case KDP_SUSPEND:
    case KDP_RESUMECPUS:
      break;
    case KDP_EXCEPTION:
      break;
    case KDP_TERMINATION:
      break;
    }

  } else {

    switch (h->request) {
    case KDP_CONNECT:
      f (l,
	 "  %8s: %d\n"
	 "  %8s: %d\n"
	 "  %8s: \"%s\"\n",
	 "req_port", p->connect_req.req_reply_port,
	 "exc_port", p->connect_req.exc_note_port,
	 "greeting", p->connect_req.greeting);
      break;
    case KDP_DISCONNECT: break;
    case KDP_HOSTINFO: break;
    case KDP_REGIONS: break;
    case KDP_MAXBYTES: break;
    case KDP_READMEM:
      f (l,
	 "  %8s: 0x%lx\n"
	 "  %8s: %d\n",
	 "addr", (unsigned long) p->readmem_req.address,
	 "nbytes", (unsigned long) p->readmem_req.nbytes);
      break;
    case KDP_WRITEMEM:
      f (l,
	 "  %8s: 0x%lx\n"
	 "  %8s: %d\n",
	 "addr", (unsigned long) p->writemem_req.address,
	 "nbytes", (unsigned long) p->writemem_req.nbytes);
      kdp_log_data (f, l, p->writemem_req.data, p->writemem_req.nbytes);
      break;
    case KDP_READREGS:
      f (l, 
	 "  %8s: 0x%lx\n"
	 "  %8s: 0x%lx\n",
	 "cpu", (unsigned long) p->readregs_req.cpu,
	 "flavor", (unsigned long) p->readregs_req.flavor);
      break;
    case KDP_WRITEREGS:
      f (l,
	 "  %8s: 0x%lx\n"
	 "  %8s: 0x%lx\n"
	 "  %8s: 0x%lx\n",
	 "cpu", (unsigned long) p->writeregs_req.cpu,
	 "flavor", (unsigned long) p->writeregs_req.flavor,
	 "nbytes", (unsigned long) p->writeregs_req.nbytes);
      kdp_log_data (f, l, p->writeregs_req.data, p->writeregs_req.nbytes);
      break;
    case KDP_LOAD:
      f (l,
	 "  %8s: \"%s\"\n",
	 "file", p->load_req.file_args);
      break;
    case KDP_IMAGEPATH: break;
    case KDP_SUSPEND: break;
    case KDP_RESUMECPUS: 
      f (l,
	 "  %8s: 0x%lx\n",
	 "mask", p->resumecpus_req.cpu_mask);
      break;
    case KDP_EXCEPTION: break;
    case KDP_TERMINATION: break;
    }    
  }
  
  f (l, "}\n");
}

kdp_return_t kdp_marshal
  (kdp_connection *c, kdp_pkt_t *p, unsigned char *s, size_t maxlen, size_t *plen)
{
#define CHECK_LEN_MAX(len, maxlen) \
  if (len > maxlen) { \
    c->logger (KDP_LOG_ERROR, \
	       "kdp_marshal: length required for packet (%lu) is greater than length provided (%lu)\n", \
	       (unsigned long) len, (unsigned long) maxlen); \
    return RR_RESOURCE; \
  }

  size_t len = 0;
  *plen = 0;

  CHECK_FATAL (c->logger != NULL);

  if (maxlen < 32) {
    c->logger (KDP_LOG_ERROR, "kdp_marshal: maximum length must be at least 32\n");
    return RR_RESOURCE;
  }

  if (p->hdr.is_reply) {

    switch (p->hdr.request) {
    case KDP_CONNECT:
      len = 12;
      write32u (s + 8, p->connect_reply.error, c->bigendian);
      break;
    case KDP_DISCONNECT:
      len = 8;
      break;
    case KDP_HOSTINFO:
      len = 20;
      write32u (s + 8, p->hostinfo_reply.cpu_mask, c->bigendian);
      write32u (s + 12, p->hostinfo_reply.cpu_type, c->bigendian);
      write32u (s + 16, p->hostinfo_reply.cpu_subtype, c->bigendian);
      break;
    case KDP_REGIONS: {
      const unsigned int REGION_SIZE = 12;
      unsigned int i = 0;
      len = 12 + (p->regions_reply.nregions * REGION_SIZE);
      CHECK_LEN_MAX (len, maxlen);
      for (i = 0; i < p->regions_reply.nregions; i++) {
	unsigned int offset = 12 + (i * REGION_SIZE);
	write32u (s + offset, p->regions_reply.regions[i].address, c->bigendian);
	write32u (s + offset + 4, p->regions_reply.regions[i].nbytes, c->bigendian);
	write32u (s + offset + 8, p->regions_reply.regions[i].protection, c->bigendian);
      }
      break;
    }
    case KDP_MAXBYTES:
      len = 12;
      write32u (s + 8, p->maxbytes_reply.max_bytes, c->bigendian);
      break;
    case KDP_READMEM:
      len = 12 + p->readmem_reply.nbytes;
      CHECK_LEN_MAX (len, maxlen);
      memcpy (s + 12, p->readmem_reply.data, len - 12);
      break;
    case KDP_WRITEMEM:
      len = 12;
      write32u (s + 8, p->writemem_reply.error, c->bigendian);
      break;
    case KDP_READREGS: {
      const unsigned int KDP_REGISTER_SIZE = 4;
      unsigned int i;
      unsigned int reglen = p->readregs_reply.nbytes;
      len = reglen + 12;
      CHECK_LEN_MAX (len, maxlen);
      if ((reglen % KDP_REGISTER_SIZE) != 0) { return RR_IP_ERROR; }
      write32u (s + 8, p->readregs_reply.error, c->bigendian);
      for (i = 0; i < (reglen / KDP_REGISTER_SIZE); i++) {
	write32u (s + 12 + (i * KDP_REGISTER_SIZE), 
		  ((unsigned long *) p->readregs_reply.data)[i], 
		  c->bigendian);
      }
      break;
    }
    case KDP_WRITEREGS:
      len = 12;
      write32u (s + 8, p->writeregs_reply.error, c->bigendian);
      break;
    case KDP_LOAD:
      len = 12;
      write32u (s + 8, p->load_reply.error, c->bigendian);
      break;
    case KDP_IMAGEPATH:
      len = 8 + strlen (p->imagepath_reply.path) + 1;
      CHECK_LEN_MAX (len, maxlen);
      memcpy (s + 8, p->imagepath_reply.path, len - 8);
      break;
    case KDP_SUSPEND:
    case KDP_RESUMECPUS:
    case KDP_EXCEPTION:
    case KDP_TERMINATION:
      len = 8;
      break;
    default:
      c->logger (KDP_LOG_ERROR, "kdp_marshal: unknown packet type for reply 0x%x\n", p->hdr.request);
      return RR_IP_ERROR;
    }

  } else {

    switch (p->hdr.request) {
    case KDP_CONNECT:
      len = 12 + strlen (p->connect_req.greeting) + 1;
      CHECK_LEN_MAX (len, maxlen);
      /* port numbers are always sent little-endian */
      write16u (s + 8, p->connect_req.req_reply_port, 0);
      write16u (s + 10, p->connect_req.exc_note_port, 0);
      memcpy (s + 12, p->connect_req.greeting, len - 12);
      break;
    case KDP_DISCONNECT:
    case KDP_HOSTINFO:
    case KDP_REGIONS:
    case KDP_MAXBYTES:
      len = 8;
      break;
    case KDP_READMEM:
      len = 16;
      write32u (s + 8, p->readmem_req.address, c->bigendian);
      write32u (s + 12, p->readmem_req.nbytes, c->bigendian);
      break;
    case KDP_WRITEMEM:
      len = 16 + p->writemem_req.nbytes;
      CHECK_LEN_MAX (len, maxlen);
      write32u (s + 8, p->writemem_req.address, c->bigendian);
      write32u (s + 12, p->writemem_req.nbytes, c->bigendian);
      memcpy (s + 16, p->writemem_req.data, p->writemem_req.nbytes);
      break;
    case KDP_READREGS:
      len = 16;
      write32u (s + 8, p->readregs_req.cpu, c->bigendian);
      write32u (s + 12, p->readregs_req.flavor, c->bigendian);
      break;
    case KDP_WRITEREGS: {
      const unsigned int KDP_REGISTER_SIZE = 4;
      unsigned int i;
      unsigned int reglen = p->writeregs_req.nbytes;
      if ((reglen % KDP_REGISTER_SIZE) != 0) { 
	c->logger (KDP_LOG_ERROR,
		   "kdp_marshal: length of register data (%u bytes) "
		   "is not a multiple of register size (%u bytes)\n", 
		   p->writeregs_req.nbytes, KDP_REGISTER_SIZE);
	return RR_IP_ERROR; 
      }
      len = reglen + 16;
      CHECK_LEN_MAX (len, maxlen);
      write32u (s + 8, p->writeregs_req.cpu, c->bigendian);
      write32u (s + 12, p->writeregs_req.flavor, c->bigendian);
      for (i = 0; i < (reglen / KDP_REGISTER_SIZE); i++) {
	write32u (s + 16 + (i * KDP_REGISTER_SIZE), 
		  ((unsigned long *) p->writeregs_req.data)[i],
		  c->bigendian);
      }
      break;
    }
    case KDP_LOAD:
      len = 8 + strlen (p->load_req.file_args) + 1;
      CHECK_LEN_MAX (len, maxlen);
      memcpy (s + 8, p->connect_req.greeting, len - 8);
      break;
    case KDP_IMAGEPATH:
    case KDP_SUSPEND:
      len = 8;
      break;
    case KDP_RESUMECPUS:
      len = 12;
      write32u (s + 8, p->resumecpus_req.cpu_mask, c->bigendian);
      break;
    case KDP_EXCEPTION: {
      const unsigned int EXCEPTION_SIZE = 16;
      unsigned int i;
      len = 12 + (p->exception.n_exc_info * EXCEPTION_SIZE);
      CHECK_LEN_MAX (len, maxlen);
      write32u (s + 8, p->exception.n_exc_info, c->bigendian);
      for (i = 0; i < p->exception.n_exc_info; i++) {
	kdp_exc_info_t *e = &p->exception.exc_info[i];
	write32u (s + 12 + (i * EXCEPTION_SIZE), e->cpu, c->bigendian);
	write32u (s + 12 + (i * EXCEPTION_SIZE) + 4, e->exception, c->bigendian);
	write32u (s + 12 + (i * EXCEPTION_SIZE) + 8, e->code, c->bigendian);
	write32u (s + 12 + (i * EXCEPTION_SIZE) + 12, e->subcode, c->bigendian);
      }
      break;
    }
    case KDP_TERMINATION:
      len = 16;
      write32u (s + 8, p->termination.term_code, c->bigendian);
      write32u (s + 12, p->termination.exit_code, c->bigendian);
      break;
    default:
      c->logger (KDP_LOG_ERROR, "kdp_marshal: unknown packet type for request 0x%x\n", p->hdr.request);
      return RR_IP_ERROR;
    }
  }
  
  CHECK_LEN_MAX (len, maxlen);

  if (len < 8) {
    c->logger (KDP_LOG_ERROR, "kdp_marshal: length of packet (%lu) is less than 8 "
	       "(an error must have occurred)\n"); 
    return RR_RESOURCE;
  }

  if (c->bigendian) {
    s[0] = (p->hdr.request & 0x7f) | (p->hdr.is_reply << 7);
  } else {
    s[0] = ((p->hdr.request & 0x7f) << 1) | (p->hdr.is_reply & 0x1);
  }    
  s[1] = p->hdr.seq;
  write16u (s + 2, len, c->bigendian);
  write32u (s + 4, p->hdr.key, c->bigendian);

  *plen = len;

  return RR_SUCCESS;
}

kdp_return_t kdp_unmarshal
  (kdp_connection *c, kdp_pkt_t *p, const unsigned char *s, size_t rlen)
{
#define CHECK_PLEN_RLEN(plen, rlen) \
  if (plen != rlen) { \
    c->logger (KDP_LOG_ERROR, \
	       "kdp_unmarshal: length contained in packet (%lu) " \
               "does not match length read from socket (%lu)\n", \
	       (unsigned long) plen, (unsigned long) rlen); \
    return RR_IP_ERROR; \
  }

#define CHECK_PLEN_LEN(plen, len) \
  if (plen != len) { \
    c->logger (KDP_LOG_ERROR, \
	       "kdp_unmarshal: length contained in packet (%lu) " \
               "does not match expected length of packet (%lu)\n", \
	       (unsigned long) plen, (unsigned long) len); \
    return RR_IP_ERROR; \
  }

#define CHECK_PLEN_MINLEN(plen, len) \
  if (plen < len) { \
    c->logger (KDP_LOG_ERROR, \
	       "kdp_unmarshal: length contained in packet (%lu) " \
               "is smaller than expected minimum packet length (%lu)\n", \
	       (unsigned long) plen, (unsigned long) len); \
    return RR_IP_ERROR; \
  }

  size_t plen = 0;

  CHECK_FATAL (c->logger != NULL);

  if (rlen < 8) { 
    c->logger (KDP_LOG_ERROR, "data length (%lu) is too small (less than %d)\n",
	       rlen, 8);
    return RR_IP_ERROR; 
  }
  if (rlen > KDP_MAX_PACKET_SIZE) { 
    c->logger (KDP_LOG_ERROR, "data length (%lu) is too large (greater than %d)\n",
	       rlen, KDP_MAX_PACKET_SIZE);
    return RR_IP_ERROR; 
  }

  if (c->bigendian) {
    p->hdr.is_reply = s[0] >> 7;
    p->hdr.request = s[0] & 0x7f;
  } else {
    p->hdr.request = s[0] >> 1;
    p->hdr.is_reply = s[0] & 0x1;
  }

  p->hdr.seq = s[1];
  plen = read16u (s + 2, c->bigendian);
  p->hdr.key = read32u (s + 4, c->bigendian);

  if (p->hdr.is_reply) {
    
    switch (p->hdr.request) {
    case KDP_CONNECT:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->connect_reply.error = read32u (s + 8, c->bigendian);
      break;
    case KDP_DISCONNECT:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_HOSTINFO:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 20);
      p->hostinfo_reply.cpu_mask = read32u (s + 8, c->bigendian);
      p->hostinfo_reply.cpu_type = read32u (s + 12, c->bigendian);
      p->hostinfo_reply.cpu_subtype = read32u (s + 16, c->bigendian);
      break;
    case KDP_REGIONS: {
      const unsigned int REGION_SIZE = 12;
      unsigned int i;
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 12);
      p->regions_reply.nregions = read32u (s + 8, c->bigendian);
      CHECK_PLEN_LEN (plen, ((p->regions_reply.nregions * REGION_SIZE) + 12));
      for (i = 0; i < p->regions_reply.nregions; i++) {
	unsigned int offset = 12 + (i * REGION_SIZE);
	p->regions_reply.regions[i].address = read32u (s + offset, c->bigendian);
	p->regions_reply.regions[i].nbytes = read32u (s + offset + 4, c->bigendian);
	p->regions_reply.regions[i].protection = read32u (s + offset + 8, c->bigendian);
      }
      break;
    }
    case KDP_MAXBYTES:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->maxbytes_reply.max_bytes = read32u (s + 8, c->bigendian);
      break;
    case KDP_READMEM:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 12);
      p->readmem_reply.error = read32u (s + 8, c->bigendian);
      p->readmem_reply.nbytes = plen - 12;
      memcpy (p->readmem_reply.data, s + 12, plen - 12);
      break;
    case KDP_WRITEMEM:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->writemem_reply.error = read32u (s + 8, c->bigendian);
      break;
    case KDP_READREGS: { 
      const unsigned int KDP_REGISTER_SIZE = 4;
      unsigned int i;
      unsigned int reglen = plen - 12;
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 12);
      p->readregs_reply.error = read32u (s + 8, c->bigendian);
      if ((reglen % KDP_REGISTER_SIZE) != 0) { 
	c->logger (KDP_LOG_ERROR, 
		   "length of register data (%u) is not an integer multiple of KDP_REGISTER_SIZE (%u)\n",
		   reglen, KDP_REGISTER_SIZE);
	return RR_IP_ERROR; 
      }
      p->readregs_reply.nbytes = reglen;
      for (i = 0; i < (reglen / KDP_REGISTER_SIZE); i++) {
	((unsigned long *) p->readregs_reply.data)[i] =
	  read32u (s + 12 + (i * KDP_REGISTER_SIZE), c->bigendian);
      }
      break;
    }
    case KDP_WRITEREGS:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->writeregs_reply.error = read32u (s + 8, c->bigendian);
      break;
    case KDP_LOAD:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->load_reply.error = read32u (s + 8, c->bigendian);
      break;
    case KDP_IMAGEPATH:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 8);
      memcpy (p->imagepath_reply.path, s + 8, plen - 8);
      break;
    case KDP_SUSPEND:
    case KDP_RESUMECPUS:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_EXCEPTION:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 8);
      break;
    case KDP_TERMINATION:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    default:
      c->logger (KDP_LOG_ERROR, "kdp_unmarshal: unknown packet type 0x%x\n", p->hdr.request);
      return RR_IP_ERROR;
    }

  } else {

    switch (p->hdr.request) {
    case KDP_CONNECT:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 12 + 1);
      /* port numbers are always sent little-endian */
      p->connect_req.req_reply_port = read16u (s + 8, 0);
      p->connect_req.exc_note_port = read16u (s + 10, 0);
      memcpy (p->connect_req.greeting, s + 12, plen - 12);
      break;
    case KDP_DISCONNECT:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_HOSTINFO:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_REGIONS:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_MAXBYTES:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_READMEM:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 16);
      p->readmem_req.address = read32u (s + 8, c->bigendian);
      p->readmem_req.nbytes = read32u (s + 12, c->bigendian);
      break;
    case KDP_WRITEMEM:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 16);
      p->writemem_req.address = read32u (s + 8, c->bigendian);
      p->writemem_req.nbytes = read32u (s + 12, c->bigendian);
      CHECK_PLEN_LEN (plen, p->writemem_req.nbytes + 16);
      memcpy (p->writemem_req.data, s + 16, plen - 16);
      break;
    case KDP_READREGS:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 16);
      p->readregs_req.cpu = read32u (s + 8, c->bigendian);
      p->readregs_req.flavor = read32u (s + 12, c->bigendian);
      break;
    case KDP_WRITEREGS: {
      const unsigned int KDP_REGISTER_SIZE = 4;
      unsigned int i;
      unsigned int reglen = plen - 16;
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 16);
      p->writeregs_req.cpu = read32u (s + 8, c->bigendian);
      p->writeregs_req.flavor = read32u (s + 12, c->bigendian);
      if ((reglen % KDP_REGISTER_SIZE) != 0) { 
	c->logger (KDP_LOG_ERROR, 
		   "length of register data (%u) is not an integer multiple of KDP_REGISTER_SIZE (%u)\n",
		   reglen, KDP_REGISTER_SIZE);
	return RR_IP_ERROR; 
      }
      p->writeregs_req.nbytes = reglen;
      for (i = 0; i < (reglen / KDP_REGISTER_SIZE); i++) {
	((unsigned long *) p->writeregs_req.data)[i] =
	  read32u (s + 16 + (i * KDP_REGISTER_SIZE), c->bigendian);
      }
      break;
    }
    case KDP_LOAD:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 8 + 1);
      memcpy (p->load_req.file_args, c + 8, plen - 8);
      break;
    case KDP_IMAGEPATH:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 8);
      break;
    case KDP_SUSPEND:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 8);
      break;
    case KDP_RESUMECPUS:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 12);
      p->resumecpus_req.cpu_mask = read32u (s + 8, c->bigendian);
      break;
    case KDP_EXCEPTION: {
      const unsigned int EXCEPTION_SIZE = 16;
      unsigned int i;
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_MINLEN (plen, 12);
      p->exception.n_exc_info = read32u (s + 8, c->bigendian);
      /* bug in KDP on NextStep <= 4.2, Rhapsody Developer */
      if ((plen == 44) && (p->exception.n_exc_info == 1)) 
	{ plen = 28; }
      CHECK_PLEN_LEN (plen, ((p->exception.n_exc_info * EXCEPTION_SIZE) + 12));
      for (i = 0; i < p->exception.n_exc_info; i++) {
	unsigned int offset = 12 + (i * EXCEPTION_SIZE);
	p->exception.exc_info[i].cpu = read32u (s + offset, c->bigendian);
	p->exception.exc_info[i].exception = read32u (s + offset + 4, c->bigendian);
	p->exception.exc_info[i].code = read32u (s + offset + 8, c->bigendian);
	p->exception.exc_info[i].subcode = read32u (s + offset + 12, c->bigendian);
      }
      break;
    }
    case KDP_TERMINATION:
      CHECK_PLEN_RLEN (plen, rlen);
      CHECK_PLEN_LEN (plen, 16);
      p->termination.term_code = read32u (s + 8, c->bigendian);
      p->termination.exit_code = read32u (s + 12, c->bigendian);
      break;
    default:
      c->logger (KDP_LOG_ERROR, "kdp_unmarshal: unknown packet type 0x%x\n", p->hdr.request);
      return RR_IP_ERROR;
    }
  }

  return RR_SUCCESS;
}
