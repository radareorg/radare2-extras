/*
 * Copyright (c) 1990--1997 Apple Computer, Inc.  All rights reserved.
 * 
 * debug_udp.c - UDP layer of remote debug protocol.
 *
 * HISTORY
 *
 * 17-Dec-97    Klee Dienes
 *      Re-wrote as kdp user library; optionally byte-swap all kdp data
 * 03-Dec-91	Doug Mitchell
 *	Converted to NRW wire protocol.
 * 25-04-91	Blaine Garst
 *  	eliminated private functions
 * 07-Jan-90	Doug Mitchell at NeXT	
 *	Created.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <netinet/in.h>

#include "kdp-udp.h"

#include "defs.h"

/* Transmit packet on port specified by host_port. */

kdp_return_t kdp_transmit_fd
  (kdp_connection *c, kdp_pkt_t *packet, int fd)
{
  char buf[KDP_MAX_PACKET_SIZE];
  size_t plen = 0;
  kdp_return_t kret;
  int ret = -1;

  CHECK_FATAL (kdp_is_bound (c));
  
  kret = kdp_marshal (c, packet, buf, KDP_MAX_PACKET_SIZE, &plen);
  if (kret != RR_SUCCESS) {
    c->logger (KDP_LOG_ERROR, "send_debug_packet: error marshalling packet: %s\n",
	       kdp_return_string (kret));
    return kret; 
  }

  c->logger (KDP_LOG_DEBUG, "kdp_transmit_fd: transmitting packet\n");
  kdp_log_packet (c->logger, KDP_LOG_DEBUG, packet);

  ret = sendto (fd, buf, plen, 0,
		(struct sockaddr *) &c->target_sin,
		sizeof (c->target_sin));
  if (ret < 0) {
    if (errno == EINTR) {
      return RR_RECV_TIMEOUT;
    } else {
      c->logger (KDP_LOG_ERROR, "kdp_transmit_fd: sendto returns %d: %s (%d)\n",
		 ret, strerror (errno), errno);
      return RR_IP_ERROR;
    }
  }
  if (ret != plen) {
    c->logger (KDP_LOG_ERROR, "kdp_transmit_fd: unable to transmit packet ",
	       "(only %lu of %lu bytes were transmitted)", ret, plen);
    return RR_BYTE_COUNT;
  }
  
  return RR_SUCCESS;
}

/* Get a packet from port specified by host_port. 
   packet is assumed to contain at most KDP_MAX_PACKET_SIZE bytes.
   recv_timeout is in milliseconds; 0 means no timeout (wait forever). */

kdp_return_t kdp_receive_fd
  (kdp_connection *c, kdp_pkt_t *packet, int fd, int timeout)
{
  int fromlen = sizeof (c->target_sin);
  int ret = -1, rlen = -1;
  kdp_return_t kret;
  unsigned char buf[KDP_MAX_PACKET_SIZE];
	
  CHECK_FATAL (kdp_is_bound (c));

  if (timeout) {

    fd_set readfds;
    struct timeval timeoutv;
		
    FD_ZERO (&readfds);
    FD_SET (fd, &readfds);
    timeoutv.tv_sec = timeout / 1000;
    timeoutv.tv_usec = (timeout % 1000) * 1000;
    ret = select (fd + 1, &readfds, 0, 0, &timeoutv);
    if (ret == 0) {
      return RR_RECV_TIMEOUT;
    } else if (ret < 0) {
      c->logger (KDP_LOG_ERROR, "kdp_receive_fd: select returns %d: %s (%d)\n",
		 ret, strerror (errno), errno);
      return RR_IP_ERROR;
    } else if (ret != 1) {
      c->logger (KDP_LOG_ERROR, "kdp_receive_fd: invalid return from select: %d\n", ret);
      return RR_IP_ERROR;
    }
  }
	
  rlen = recvfrom (fd, buf, KDP_MAX_PACKET_SIZE, 0,
		  (struct sockaddr *) &c->target_sin, &fromlen);
  if (rlen < 0) {
    if (errno == EINTR) {
      return RR_RECV_TIMEOUT;
    } else {
      c->logger (KDP_LOG_ERROR, "kdp_receive_fd: recvfrom returns %d: %s (%d)\n",
		 rlen, strerror (errno), errno);
      return RR_IP_ERROR;
    }
  }
  
  kret = kdp_unmarshal (c, packet, buf, rlen);
  if (kret != RR_SUCCESS) { 
    c->logger (KDP_LOG_ERROR, "kdp_receive_fd: error unmarshalling packet: %s\n",
	       kdp_return_string (kret));
    return kret; 
  }

  c->logger (KDP_LOG_DEBUG, "kdp_receive_fd: received packet\n");
  kdp_log_packet (c->logger, KDP_LOG_DEBUG, packet);

  return RR_SUCCESS;
}

kdp_return_t kdp_receive (kdp_connection *c, kdp_pkt_t *packet, int to)
{
  fd_set readfds, writefds, excfds;
  struct timeval timeout, *ptimeout = NULL;
  int maxfd = 0;
  int ret = 0;

  CHECK_FATAL (kdp_is_bound (c));

  if (c->excfd > maxfd) { maxfd = c->excfd; }
  if (c->reqfd > maxfd) { maxfd = c->reqfd; }

  FD_ZERO (&readfds);
  FD_ZERO (&writefds);
  FD_ZERO (&excfds);

  FD_SET (c->excfd, &readfds);
  FD_SET (c->reqfd, &readfds);

  if (to > 0) {
    timeout.tv_sec = to / 1000;
    timeout.tv_usec = (to % 1000) * 1000;
    ptimeout = &timeout;
  } else {
    ptimeout = NULL;
  }

  ret = select (maxfd + 1, &readfds, &writefds, &excfds, ptimeout);
  if (ret < 0) {
    if (errno == EINTR) {
      return RR_RECV_INTR;
    } else {
      c->logger (KDP_LOG_ERROR, "kdp_receive: select returns %d: %s (%d)\n",
		 ret, strerror (errno), errno);
      return RR_IP_ERROR;
    }
  }

  if (FD_ISSET (c->excfd, &readfds)) {
    return kdp_receive_fd (c, packet, c->excfd, 1);
  } else if (FD_ISSET (c->reqfd, &readfds)) {
    return kdp_receive_fd (c, packet, c->reqfd, 1);
  } else {
    return RR_RECV_TIMEOUT;
  }
}

void kdp_set_timeouts (kdp_connection *c, int timeout, int retries)
{
  c->receive_timeout = timeout;
  c->retries = retries;
}

static kdp_return_t kdp_bind_socket
  (kdp_connection *c, unsigned short port, unsigned short *pret, int *fd)
{
  struct sockaddr_in local_sin;
  int retsize;
  int retfd;
  int ret;

  CHECK_FATAL (pret != NULL);
  CHECK_FATAL (fd != NULL);

  retfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (retfd < 0) {
    c->logger (KDP_LOG_ERROR, "kdp_bind_socket: errror creating local socket: %s\n",
	       strerror (errno));
    return RR_RESOURCE;
  }

  memset (&local_sin, 0, sizeof (struct sockaddr_in));
  local_sin.sin_family = AF_INET;
  local_sin.sin_addr.s_addr = INADDR_ANY;
  local_sin.sin_port = htons (port);
  ret = bind (retfd, (struct sockaddr *) &local_sin, sizeof (struct sockaddr_in));

  if (ret < 0) {
    c->logger (KDP_LOG_ERROR, "kdp_bind_socket: unable to bind socket: %s\n",
	       strerror (errno));
    return RR_RESOURCE;
  }

  retsize = sizeof (struct sockaddr_in);
  ret = getsockname (retfd, (struct sockaddr *) &local_sin, &retsize);
  if (ret < 0) {
    c->logger (KDP_LOG_ERROR, "kdp_bind_socket: unable find socket address: %s\n",
	       strerror (errno));
    return RR_RESOURCE;
  }
  
  *fd = retfd;
  *pret = ntohs (local_sin.sin_port);
  return RR_SUCCESS;
}

static kdp_return_t kdp_bind_remote
  (struct kdp_connection *c, const char *target, int port)
{
  struct hostent *host;
  struct in_addr addr;
  int ret;

  CHECK_FATAL (! kdp_is_connected (c));
  CHECK_FATAL (! kdp_is_bound (c));

  c->logger (KDP_LOG_DEBUG, "kdp_bind_remote: binding to host \"%s\"\n", target);
	
  /* Set up two local UDP sockets. */
  
  ret = kdp_bind_socket (c, INADDR_ANY, &c->reqport, &c->reqfd);
  if (ret != RR_SUCCESS) { return ret; }

  /* Now the exception port. */

  ret = kdp_bind_socket (c, INADDR_ANY, &c->excport, &c->excfd);
  if (ret != RR_SUCCESS) { return ret; }

  /* Set up a sockaddr_in for target host and connect to the target. */

  host = gethostbyname ((char *) target);
  if (host == NULL)
    {
      ret = inet_aton (target, &addr);
      if (ret == 1)
	host = gethostbyaddr ((char *) &addr, 4, AF_INET);
    }
  if (host != NULL)
    {
      c->target_sin.sin_family = host->h_addrtype;
      c->target_sin.sin_port = htons (port);
      memcpy (&c->target_sin.sin_addr, host->h_addr, host->h_length);
      
      c->port = port;
      c->bound = 1;
      return RR_SUCCESS;
    }
  if (ret == 1) 
    {
      c->target_sin.sin_family = AF_INET;
      c->target_sin.sin_port = htons (port);
      memcpy (&c->target_sin.sin_addr, &addr, sizeof (struct in_addr));
      c->port = port;
      c->bound = 1;
      return RR_SUCCESS;
    }    

  c->logger (KDP_LOG_ERROR, "kdp_bind_remote: unable to resolve host \"%s\"\n", target);
  return RR_LOOKUP;
}

void kdp_reset (kdp_connection *c)
{
  memset (c, 0, sizeof (kdp_connection));

  c->logger = NULL;

  c->receive_timeout = 0;
  c->retries = 0;

  c->port = -1;
  c->bigendian = -1;

  c->session_key = 0;

  c->reqfd = -1;
  c->reqport = 0;
  c->excfd = -1;
  c->excport = 0;

  c->seqno = 0;
  c->exc_seqno = 0;

  memset (&c->target_sin, 0, sizeof (struct sockaddr_in));

  c->connected = 0;
  c->bound = 0;
  c->timed_out = 0;
}

void kdp_set_big_endian (kdp_connection *c)
{
  c->bigendian = 1;
}

void kdp_set_little_endian (kdp_connection *c)
{
  c->bigendian = 0;
}

kdp_return_t kdp_create
(kdp_connection *c, void (*logger) (kdp_log_level l, const char *s, ...),
 const char *target, unsigned int port,
 int timeout, int retries)
{
  kdp_return_t ret;

  CHECK_FATAL (! kdp_is_connected (c));
  CHECK_FATAL (! kdp_is_bound (c));

  kdp_reset (c);

  c->logger = logger;

  c->bigendian = 0;

  c->seqno = 0;
  c->exc_seqno = 0;

  /* Allocate and initialize in/out packets. */

  c->response = (kdp_pkt_t *) malloc (KDP_MAX_PACKET_SIZE);
  if (c->response == NULL) { return RR_RESOURCE; }
  
  c->request = (kdp_pkt_t *) malloc (KDP_MAX_PACKET_SIZE);
  if (c->request == NULL) { return RR_RESOURCE; }

  c->saved_exception = (kdp_pkt_t *) malloc (KDP_MAX_PACKET_SIZE);
  if (c->saved_exception == NULL) { return RR_RESOURCE; }
  
  memset (c->request, 0, KDP_MAX_PACKET_SIZE);
  memset (c->response, 0, KDP_MAX_PACKET_SIZE);
  memset (c->saved_exception, 0, KDP_MAX_PACKET_SIZE);

  c->receive_timeout = timeout;
  c->retries = retries;

  /* Set up UDP ports and sockets. */

  ret = kdp_bind_remote (c, target, port);
  if (ret != RR_SUCCESS) { return ret; }

  return RR_SUCCESS;
}

kdp_return_t kdp_destroy (kdp_connection *c)
{
  /* CHECK_FATAL (! kdp_is_connected (c)); */
  CHECK_FATAL (kdp_is_bound (c));

  CHECK_FATAL (c->request != NULL);
  CHECK_FATAL (c->response != NULL);
  CHECK_FATAL (c->saved_exception != NULL);

  free (c->request);
  free (c->response);
  free (c->saved_exception);

  CHECK_FATAL (close (c->reqfd) == 0);
  CHECK_FATAL (close (c->excfd) == 0);

  kdp_reset (c);

  return RR_SUCCESS;
}

int kdp_is_bound (kdp_connection *c)
{
  if (c->bound) { 
    CHECK_FATAL (c->logger != NULL);
  }    
  return c->bound;
}

int kdp_is_connected (kdp_connection *c)
{
  if (c->connected) {
    CHECK_FATAL (c->logger != NULL);
  }
  return c->connected;
}

kdp_return_t kdp_transmit_debug (kdp_connection *c, kdp_pkt_t *packet) 
{
  CHECK_FATAL (kdp_is_bound (c));
  return kdp_transmit_fd (c, packet, c->reqfd);
}

kdp_return_t kdp_transmit_exception (kdp_connection *c, kdp_pkt_t *packet)
{
  CHECK_FATAL (kdp_is_bound (c));
  return kdp_transmit_fd (c, packet, c->excfd);
}

kdp_return_t kdp_receive_debug (kdp_connection *c, kdp_pkt_t *packet, int timeout)
{
  CHECK_FATAL (kdp_is_bound (c));
  return kdp_receive_fd (c, packet, c->reqfd, timeout);
}

kdp_return_t kdp_receive_exception (kdp_connection *c, kdp_pkt_t *packet, int timeout)
{
  CHECK_FATAL (kdp_is_bound (c));
  return kdp_receive_fd (c, packet, c->excfd, timeout);
}
