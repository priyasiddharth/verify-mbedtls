add_library(seahorn_mbedtls_util_lib STATIC seahorn_mbedtls_util.c)
target_include_directories(seahorn_mbedtls_util_lib
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/)
sea_attach_bc(seahorn_mbedtls_util_lib)
