add_library(ssl_msg_close_notify_env STATIC
  ssl_msg_close_notify_env.c)
target_include_directories(ssl_msg_close_notify_env
  PRIVATE ${MBEDTLS_DIR}/include/
    ${MBEDTLS_DIR}/library/
    ${PROJECT_SOURCE_DIR}/seahorn/include/
  )
sea_attach_bc(ssl_msg_close_notify_env)
