add_library(ssl_msg_close_notify_harness STATIC
  ${MBEDTLS_DIR}/library/ssl_msg.c
  ssl_msg_close_notify_harness.c)
target_include_directories(ssl_msg_close_notify_harness
  PRIVATE ${MBEDTLS_DIR}/include/
    ${MBEDTLS_DIR}/library/
    ${PROJECT_SOURCE_DIR}/seahorn/include/
)
sea_overlink_libraries(ssl_msg_close_notify_harness ssl_msg_close_notify_env.ir)
sea_attach_bc(ssl_msg_close_notify_harness)
sea_add_unsat_test(ssl_msg_close_notify_harness)
