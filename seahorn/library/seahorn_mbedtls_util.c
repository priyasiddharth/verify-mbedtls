#include "common.h" // allow access to private members of ssl_context

#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>

#include <seahorn_mbedtls_util.h>

void init_outgoing_buf(struct mbedtls_ssl_context *ssl) {
  // setup outgoing data
  ND_ALIGNED64_SIZE_T(out_buf_len);
  assume(out_buf_len <= GLOBAL_BUF_MAX_SIZE);
  unsigned char *out_buf = (unsigned char *)malloc(out_buf_len);
  ssl->out_len = (unsigned char *)&out_buf_len;
  // setup out header
  ND_ALIGNED64_SIZE_T(out_header_start);

  ssl->out_hdr = out_buf + out_header_start;
  ND_ALIGNED64_SIZE_T(out_header_len);
  // setup iv
  size_t out_iv_len = nd_size_t();
  ssl->out_iv = out_buf + out_header_len;
  // setup out msg
  ssl->out_msg = out_buf + out_iv_len;
  ssl->out_msglen = nd_size_t();
  assume(IS_ALIGN64(ssl->out_msglen));
  assume(ssl->out_msglen >= 2);
  assume(out_header_len <= out_buf_len);
  assume(out_iv_len <= out_buf_len);
  assume(ssl->out_msglen <= out_buf_len);
  assume(out_header_len + out_iv_len + ssl->out_msglen == out_buf_len);
}

void init_incoming_buf(struct mbedtls_ssl_context *ssl) {
  // setup ingoing data
  ND_ALIGNED64_SIZE_T(in_buf_len);
  assume(in_buf_len <= GLOBAL_BUF_MAX_SIZE);
  unsigned char *in_buf = (unsigned char *)malloc(in_buf_len);
  ssl->in_len = (unsigned char *)&in_buf_len;
  // setup in header
  ND_ALIGNED64_SIZE_T(in_header_start);
  ssl->in_hdr = in_buf + in_header_start;
  ND_ALIGNED64_SIZE_T(in_header_len);
  // setup iv
  ND_ALIGNED64_SIZE_T(in_iv_len);
  ssl->in_iv = in_buf + in_header_len;
  // setup in msg
  ssl->in_msg = in_buf + in_iv_len;
  ssl->in_msglen = nd_size_t();
  assume(IS_ALIGN64(ssl->in_msglen));
  assume(ssl->in_msglen >= 2);
  assume(in_header_len <= in_buf_len);
  assume(in_iv_len <= in_buf_len);
  assume(ssl->in_msglen <= in_buf_len);
  assume(in_header_len + in_iv_len + ssl->in_msglen == in_buf_len);
}

bool outgoing_buf_valid(struct mbedtls_ssl_context *ssl) {
  return sea_is_dereferenceable(ssl->out_msg, ssl->out_msglen);
}

bool incoming_buf_valid(struct mbedtls_ssl_context *ssl) {
  return sea_is_dereferenceable(ssl->in_msg, ssl->in_msglen);
}
