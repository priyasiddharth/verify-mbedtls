add_library(seahorn_mbedtls_util_lib STATIC seahorn_mbedtls_util.c)
target_compile_definitions(seahorn_mbedtls_util_lib PRIVATE NUM_OUT_RECORDS=${NUM_OUT_RECORDS})
target_compile_definitions(seahorn_mbedtls_util_lib PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)  
target_compile_definitions(seahorn_mbedtls_util_lib PRIVATE USE_OWNSEM=0)  
target_include_directories(seahorn_mbedtls_util_lib
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/)
sea_attach_bc(seahorn_mbedtls_util_lib)

add_library(seahorn_mbedtls_util_ownsem_lib STATIC seahorn_mbedtls_util.c)
target_compile_definitions(seahorn_mbedtls_util_ownsem_lib PRIVATE NUM_OUT_RECORDS=${NUM_OUT_RECORDS})
target_compile_definitions(seahorn_mbedtls_util_ownsem_lib PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)  
target_compile_definitions(seahorn_mbedtls_util_ownsem_lib PRIVATE USE_OWNSEM=1)  
target_include_directories(seahorn_mbedtls_util_ownsem_lib
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/)
sea_attach_bc(seahorn_mbedtls_util_ownsem_lib)
