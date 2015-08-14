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

#include "kdp-transactions.h"
#include "kdp-protocol.h"

#include <stdlib.h>

#include "defs.h"

static kdp_return_t kdp_exception_reply
(kdp_connection *c, kdp_pkt_t *response)
{
  kdp_return_t kdpret;
  kdp_exception_ack_t ack;

  CHECK_FATAL (kdp_is_connected (c));
  CHECK_FATAL (kdp_is_bound (c));

  ack.hdr.request = KDP_EXCEPTION;
  ack.hdr.is_reply = 1;
  ack.hdr.seq = response->exception.hdr.seq;
  ack.hdr.key = response->exception.hdr.key;

  kdpret = kdp_transmit_exception (c, (kdp_pkt_t *) &ack);
  if (kdpret != RR_SUCCESS) {
    c->logger (KDP_LOG_ERROR, "kdp_exception_reply: unable to acknowledge exception: %s\n",
	       kdp_return_string (kdpret));
  }

  return kdpret;
}

kdp_return_t kdp_exception_wait
(kdp_connection *c, kdp_pkt_t *response, int timeout)
{
  if (c->saved_exception_pending) {
    memcpy (response, c->saved_exception, KDP_MAX_PACKET_SIZE);
    c->saved_exception_pending = 0;
    c->logger (KDP_LOG_DEBUG, "kdp_exception_wait: "
	       "returning previously saved exception (sequence number is %d)",
	       response->hdr.seq);
    return RR_SUCCESS;
  }

  for (;;) {
    
    kdp_return_t kdpret;

    kdpret = kdp_receive_exception (c, response, timeout);
    if (kdpret != RR_SUCCESS) { return kdpret; }
    
    kdpret = kdp_exception_reply (c, response);
    if (kdpret != RR_SUCCESS) { return kdpret; }

    if (response->hdr.seq == c->exc_seqno) {
      c->exc_seqno = (c->exc_seqno + 1) % 256;
      c->logger (KDP_LOG_DEBUG, "kdp_exception_wait: "
		 "returning previously saved exception (sequence number is %d)",
		 response->hdr.seq);
      break;
    } else if (((response->hdr.seq + 1) % 256) == c->exc_seqno) {
      /* duplicate of previous exception */
      c->logger (KDP_LOG_DEBUG, "kdp_reply_wait: "
		 "ignoring duplicate of previous exception (sequence number was %d)\n",
		 response->hdr.seq);
      continue;
    } else {
      c->logger (KDP_LOG_ERROR, "kdp_exception_wait: "
		 "unexpected sequence number for exception (expected %d, got %d)\n",
		 c->exc_seqno, response->hdr.seq);
      continue;
    }
  }    

  return RR_SUCCESS;
}

kdp_return_t kdp_reply_wait
(kdp_connection *c, kdp_pkt_t *response, int timeout)
{
  for (;;) {
    
    kdp_return_t kdpret;

    kdpret = kdp_receive (c, response, timeout);
    if (kdpret != RR_SUCCESS) {
      c->logger (KDP_LOG_ERROR, "kdp_reply_wait: error from kdp_receive: %s\n",
		 kdp_return_string (kdpret));
      return kdpret; 
    }
    
    if (response->hdr.request == KDP_EXCEPTION) {

      kdpret = kdp_exception_reply (c, response);
      if (kdpret != RR_SUCCESS) { 
	c->logger (KDP_LOG_ERROR, "kdp_reply_wait: error from kdp_exception_reply: %s\n",
		   kdp_return_string (kdpret));
	return kdpret;
      }
	
      if (response->hdr.seq == c->exc_seqno) {
	c->exc_seqno = (c->exc_seqno + 1) % 256;
	/* save for future processing */
	if (c->saved_exception_pending) {
	  c->logger (KDP_LOG_ERROR, "kdp_reply_wait: "
		     "unable to save exception for future processing; ignoring\n");
	  c->logger (KDP_LOG_ERROR, "kdp_reply_wait: "
		     "exception had sequence number %d\n", response->hdr.seq);
	  return RR_IP_ERROR;
	}
	c->logger (KDP_LOG_DEBUG, "kdp_reply_wait: "
		   "saving exception for future processing (sequence number is %d)\n",
		   response->hdr.seq);
	memcpy (c->saved_exception, response, KDP_MAX_PACKET_SIZE);
	c->saved_exception_pending = 1;
	continue;
      } else if (((response->hdr.seq + 1) % 256) == c->exc_seqno) {
	/* duplicate of previous exception */
	c->logger (KDP_LOG_DEBUG, "kdp_reply_wait: "
		   "ignoring duplicate of previous exception (sequence number was %d)\n",
		   response->hdr.seq);
	continue;
      } else {
	c->logger (KDP_LOG_ERROR, "kdp_reply_wait: "
		   "unexpected sequence number for exception (expected %d, got %d)\n",
		   c->exc_seqno, response->hdr.seq);
	continue;
      }

    } else {

      if (response->hdr.seq == c->seqno) {
	c->seqno = (c->seqno + 1) % 256;
	/* return reply */
	c->logger (KDP_LOG_DEBUG, "kdp_reply_wait: "
		   "returning reply (sequence number is %d)\n",
		   response->hdr.seq);
	break;
      } else if (((response->hdr.seq + 1) % 256) == c->exc_seqno) {
	/* duplicate of previous response */
	c->logger (KDP_LOG_DEBUG, "kdp_reply_wait: "
		   "ignoring duplicate of previous reply (sequence number was %d)\n",
		   response->hdr.seq);
	continue;
      } else {
	c->logger (KDP_LOG_ERROR, "kdp_reply_wait: "
		   "unexpected sequence number for reply (expected %d, got %d)\n",
		   c->seqno, response->hdr.seq);
	continue;
      }
    }
  }

  return RR_SUCCESS;
}

kdp_return_t kdp_transaction
  (kdp_connection *c, kdp_pkt_t *request, kdp_pkt_t *response, char *name)
{
  kdp_return_t rtn;
  int retries = c->retries;

  CHECK_FATAL (kdp_is_bound (c));

  CHECK_FATAL (request != NULL);
  CHECK_FATAL (response != NULL);
  CHECK_FATAL (name != NULL);

  request->hdr.seq = c->seqno;
  request->hdr.key = c->session_key;
  request->hdr.is_reply = 0;

  rtn = RR_RECV_TIMEOUT;

  while (retries--) {

    rtn = kdp_transmit_debug (c, request);
    if (rtn != RR_SUCCESS) { break; }

    if (c->timed_out) { 
      rtn = kdp_reply_wait (c, response, 1);
      if (rtn == RR_RECV_TIMEOUT) { return rtn; }
      c->logger (KDP_LOG_INFO, "kdp_transaction (%s): "
		 "host responding; continuing transactions\n", name);
    } else {
      rtn = kdp_reply_wait (c, response, c->receive_timeout);
    }

    if (rtn == RR_RECV_TIMEOUT) {
      c->logger (KDP_LOG_INFO, "kdp_transaction (%s): transation timed out\n", name);
      c->logger (KDP_LOG_INFO, "kdp_transaction (%s): re-sending transaction\n", name);
      continue;
    }

    break;
  }

  if (rtn == RR_RECV_TIMEOUT) {
    c->logger (KDP_LOG_INFO, "kdp_transaction (%s): host not responding; will retry\n", name);
    c->timed_out = 1;
    return rtn;
  }

  if (rtn != RR_SUCCESS) {
    return rtn;
  }

  /* Check for correct session key (except for CONNECT requests). */
  if ((request->hdr.request != KDP_CONNECT) && (response->hdr.key != c->session_key)) {
    c->logger (KDP_LOG_ERROR, "kdp_transaction (%s): invalid session key %d (expected %d)\n", 
	       name, response->hdr.key, c->session_key);
    return RR_BAD_ACK;
  }
  
  if (! response->hdr.is_reply) {
    c->logger (KDP_LOG_ERROR, "kdp_transaction (%s): "
	       "response was not tagged as a reply packet\n", name);
    return RR_BAD_ACK;
  }
  
  if (response->hdr.request != request->hdr.request) {
    c->logger (KDP_LOG_ERROR, "kdp_transaction (%s):"
	       "packet type of request (%d) does not match packet type of reply (%d)\n", 
	       name, request->hdr.request, response->hdr.request);
    return RR_BAD_ACK;
  }

  return RR_SUCCESS;
}

/* Perform connect sequence. Assumes a disconnected state.

   If a connect ack is lost, the target wedges. That's because all we
   can do is retransmit the connect request, with a (most likely) wrong
   session key and a zero sequence number. The target thinks it's
   connected, so it rejects these requests. */

kdp_return_t kdp_connect 
(kdp_connection *c)
{
  kdp_return_t ret;

  CHECK_FATAL (kdp_is_bound (c));
  CHECK_FATAL (! kdp_is_connected (c));

  /* Do a connect transaction. */

  c->request->connect_req.hdr.request = KDP_CONNECT;
  c->request->connect_req.req_reply_port = c->reqport;
  c->request->connect_req.exc_note_port  = c->excport;
  strncpy (c->request->connect_req.greeting, "", 64);
  c->request->connect_req.greeting[63] = '\0';

  ret = kdp_transaction (c, c->request, c->response, "remote_connect");
  if (ret != RR_SUCCESS) { return ret; }

  if (c->response->writemem_reply.error) {
    c->logger (KDP_LOG_ERROR, "kdp_connect: %s\n",
	       kdp_return_string (c->response->connect_reply.error));
    return RR_CONNECT;
  }

  c->session_key = c->response->hdr.key;
  c->connected = 1;

  return RR_SUCCESS;
}

kdp_return_t kdp_disconnect (kdp_connection *c)
{
  kdp_return_t ret; 

  CHECK_FATAL (kdp_is_connected (c));

  c->request->disconnect_req.hdr.request = KDP_DISCONNECT;
  ret = kdp_transaction (c, c->request, c->response, "kdp_disconnect");

  if (ret != RR_SUCCESS) { return ret; }
  c->connected = 0;

  return RR_SUCCESS;
}
