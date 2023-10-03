#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

extern int ssl_get_timer(void *);
extern int get_last_read_record_retval(void);

DEFINE_UNIT_PROOF(mbedtls_ssl_recv_flight_completed) {
  // NOTE: setup the precondition
  sea_tracking_on();
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup incoming & outgoing data
  init_incoming_buf(&ssl);
  init_outgoing_buf(&ssl);
  struct mbedtls_ssl_flight_item *flight =
      (struct mbedtls_ssl_flight_item *)malloc(
          sizeof(struct mbedtls_ssl_flight_item));
  memhavoc(flight, sizeof(mbedtls_ssl_flight_item));
  flight->next = NULL;
  ssl.handshake->flight = flight;
  /* // set in msg type */
  /* assume(ssl.in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE); */
  /* // setup recv fn */
  /* ssl.f_get_timer = &ssl_get_timer; */
  /* // setup buffer */
  /* ND_ALIGNED64_SIZE_T(buf_size); */
  /* assume(buf_size < ssl.in_msglen); */
  /* ND_ALIGNED64_SIZE_T(in_offset_pos); */
  /* if (nd_bool()) { */
  /*   assume(in_offset_pos < ssl.in_msglen); */
  /*   ssl.in_offt = ssl.in_msg + in_offset_pos; */
  /* } else { */
  /*   assume(in_offset_pos == 0); */
  /*   ssl.in_offt = NULL; */
  /* } */
  /* size_t sentinel_idx = nd_size_t(); // byte aligned */
  /* assume(sentinel_idx < (ssl.in_msglen - in_offset_pos)); */
  /* unsigned char sentinel_val = (ssl.in_offt == NULL) */
  /*                                  ? ssl.in_msg[sentinel_idx] */
  /*                                  : ssl.in_offt[sentinel_idx]; */
  /* unsigned char *buf = (unsigned char *)malloc(buf_size); */
  /* ND_ALIGNED64_SIZE_T(len); */
  /* assume(len < (ssl.in_msglen - in_offset_pos)); */
  /* assume(len < buf_size); */
  /* assume(sentinel_idx < len); */
  // NOTE: call the SUT
  mbedtls_ssl_recv_flight_completed(&ssl);
  // NOTE: Postcondition check
  sassert(!sea_is_alloc((char *)ssl.handshake->flight));
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_recv_flight_completed);
  return 0;
}
