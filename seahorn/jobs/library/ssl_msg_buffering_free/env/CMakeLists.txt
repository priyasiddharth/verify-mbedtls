# This file has been generated by the add_job script
add_library(ssl_msg_buffering_free_env STATIC ssl_msg_buffering_free_env.cc)
target_include_directories(ssl_msg_buffering_free_env
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/
  ${SEAMOCK_ROOT}/include)
sea_attach_bc_cc(ssl_msg_buffering_free_env)
    