extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

extern "C" {
LAZY_MOCK_FUNCTION(mbedtls_ssl_prepare_handshake_record, int,
                   (mbedtls_ssl_context *))
}
