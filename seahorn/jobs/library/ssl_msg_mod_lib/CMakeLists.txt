add_library(ssl_mod_msg STATIC
  ${MBEDTLS_MOD_DIR}/library/ssl_msg.c)

  target_compile_definitions(ssl_mod_msg PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)

  target_include_directories(ssl_mod_msg
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/
  ${SEAMOCK_ROOT}/include)
sea_attach_bc(ssl_mod_msg)
set(LLVMIR_OPT ${SEA_PP})
llvmir_attach_opt_pass_target(TARGET ssl_mod_msg.opt.ir DEPENDS ssl_mod_msg.ir
  "--externalize-function=^ssl_*" "-externalize-functions-delete=false" "--externalize-fns")
