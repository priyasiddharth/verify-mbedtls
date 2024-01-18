extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

extern "C" {
SUC_MOCK_FUNCTION(mbedtls_ssl_write_version,
                  (unsigned char *, int, mbedtls_ssl_protocol_version))

ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_space_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_payload_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flush_output, (mbedtls_ssl_context *))
}
