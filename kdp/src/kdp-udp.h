#ifndef _KDB_DEBUG_UDP_H_
#define _KDB_DEBUG_UDP_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "kdp-protocol.h"

struct kdp_connection {

  /* connection information */

  kdp_log_function *logger;

  kdp_pkt_t *request;
  kdp_pkt_t *response;

  kdp_pkt_t *exc_request;
  kdp_pkt_t *exc_response;

  kdp_pkt_t *saved_exception;
  int saved_exception_pending;

  unsigned int receive_timeout; 
  unsigned int retries;

  int port;
  int bigendian;

  unsigned int session_key;	 /* obtained from target */

  int reqfd;			 /* socket for normal target */
  unsigned short reqport;	 /* udp port in req_reply_fd */
  int excfd;			 /* socket for target exceptions */
  unsigned short excport;	 /* udp port in excep_fd */

  unsigned int seqno;		 /* next request seq # */
  unsigned int exc_seqno;

  struct sockaddr_in target_sin; /* target communication addrs */

  int connected;
  int bound;
  int timed_out;
};

typedef struct kdp_connection kdp_connection;

kdp_return_t kdp_transmit_fd
  (kdp_connection *c, kdp_pkt_t *packet, int fd);

kdp_return_t kdp_receive_fd
  (kdp_connection *c, kdp_pkt_t *packet, int fd, int timeout);

kdp_return_t kdp_transmit_debug
  (kdp_connection *c, kdp_pkt_t *packet);

kdp_return_t kdp_transmit_exception
  (kdp_connection *c, kdp_pkt_t *packet);

kdp_return_t kdp_receive_debug
   (kdp_connection *c, kdp_pkt_t *packet, int timeout);

kdp_return_t kdp_receive_exception
  (kdp_connection *c, kdp_pkt_t *packet, int timeout);

kdp_return_t kdp_receive
  (kdp_connection *c, kdp_pkt_t *packet, int timeout);

const char *kdp_return_string
  (kdp_return_t error);

kdp_return_t kdp_create
  (kdp_connection *c, kdp_log_function *logger, 
   const char *target, unsigned int port, 
   int timeout, int retries);

kdp_return_t kdp_destroy 
  (kdp_connection *c);

void kdp_set_timeouts
  (kdp_connection *c, int timeout, int retries);

void kdp_set_big_endian (kdp_connection *c);
void kdp_set_little_endian (kdp_connection *c);

void kdp_reset (kdp_connection *c);

int kdp_is_bound (kdp_connection *c);
int kdp_is_connected (kdp_connection *c);

#endif /* _KDB_DEBUG_UDP_H_ */
