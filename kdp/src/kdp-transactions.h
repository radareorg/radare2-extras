#ifndef _KDB_DEBUG_TRANSACTIONS_H_
#define _KDB_DEBUG_TRANSACTIONS_H_

#include "kdp-udp.h"

kdp_return_t kdp_exception_wait
  (kdp_connection *c, kdp_pkt_t *response, int timeout);

kdp_return_t kdp_reply_wait
  (kdp_connection *c, kdp_pkt_t *response, int timeout);

kdp_return_t kdp_transaction
  (kdp_connection *c, kdp_pkt_t *request, kdp_pkt_t *response, char *name);

kdp_return_t kdp_connect (kdp_connection *c);

kdp_return_t kdp_disconnect (kdp_connection *c);

#endif /* _KDB_DEBUG_TRANSACTIONS_H_ */
