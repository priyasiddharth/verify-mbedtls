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
  sea_printf("out_buf addr:%x\n", out_buf);
#if USE_OWNSEM == 1 
  SEA_MKOWN(out_buf);
  SEA_WRITE_CACHE(out_buf, 0);
  // SEA_MOVE2MEM(&(ssl->out_buf),out_buf)
/* 
#else     
  ssl->out_buf = out_buf; */
#endif  
  ssl->out_buf = out_buf;
  sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) (ssl->out_buf), 0);
  //size_t count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl));

  // assert(sea_is_dereferenceable(ssl->conf, 1));  
  ssl->out_len = (unsigned char *)&out_buf_len;
  // setup out header
  ND_ALIGNED64_SIZE_T(out_header_start);
  assume(out_header_start < out_buf_len);
  ssl->out_hdr = out_buf + out_header_start;
  ND_ALIGNED64_SIZE_T(out_header_len);
  assume(out_header_len > 4);
  assume(out_header_len < out_buf_len); 

  // setup iv
  ND_ALIGNED64_SIZE_T(out_iv_len);
  assume(out_iv_len < out_buf_len); 
  ssl->out_iv = ssl->out_hdr + out_header_len;
  // setup out msg
  ssl->out_msg = ssl->out_iv + out_iv_len;
  ssl->out_msglen = nd_size_t();
  assume(IS_ALIGN64(ssl->out_msglen));
  assume(ssl->out_msglen >= 2);
  assume(out_header_len < out_buf_len);
  assume(out_header_start < out_buf_len);

  assume(out_iv_len < out_buf_len);
  assume(ssl->out_msglen < out_buf_len);
  
  assume(out_header_start + out_header_len + out_iv_len + ssl->out_msglen + 1 <
         out_buf_len);
  // havoc out_msg
  ssl->out_buf_len = out_buf_len;
  memhavoc(ssl->out_buf, ssl->out_buf_len);
  // sassert(sea_is_dereferenceable(ssl->conf, 1));  
  sea_printf("out_buf addr:%x\n", out_buf);
  sea_printf("ssl.out_buf addr:%x\n", ssl->out_buf);
  sea_printf("outgoing buffer: header_start:%x, iv_start:%x, msg_start:%x\n",
             ssl->out_hdr, ssl->out_iv, ssl->out_msg);
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
  assume(in_header_start < in_buf_len);

  assume(in_header_len < in_buf_len);
  assume(in_iv_len < in_buf_len);
  assume(ssl->in_msglen < in_buf_len);
  assume(in_header_start + in_header_len + in_iv_len + ssl->in_msglen ==
         in_buf_len);
  sea_printf("incoming buffer: header_start:%x, iv_start:%x, msg_start:%x\n",
             ssl->in_hdr, ssl->in_iv, ssl->in_msg);
}

bool outgoing_buf_valid(struct mbedtls_ssl_context *ssl) {
  return sea_is_dereferenceable(ssl->out_msg, ssl->out_msglen);
}

bool incoming_buf_valid(struct mbedtls_ssl_context *ssl) {
  return sea_is_dereferenceable(ssl->in_msg, ssl->in_msglen);
}
