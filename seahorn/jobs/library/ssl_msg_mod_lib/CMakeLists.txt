add_library(ssl_mod_ownsem_msg STATIC
  ${MBEDTLS_MOD_DIR}/library/ssl_msg.c)

  target_compile_definitions(ssl_mod_ownsem_msg PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)

  target_include_directories(ssl_mod_ownsem_msg
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/
  ${SEAMOCK_ROOT}/include)
sea_attach_bc(ssl_mod_ownsem_msg)
set(LLVMIR_OPT ${SEA_PP})
llvmir_attach_opt_pass_target(TARGET ssl_mod_ownsem_msg.opt.ir DEPENDS ssl_mod_ownsem_msg.ir
  "--externalize-function=^ssl_*" "-externalize-functions-delete=false" "--externalize-fns")


add_library(ssl_mod_shadow_msg STATIC
  ${MBEDTLS_MOD2_DIR}/library/ssl_msg.c)

  target_compile_definitions(ssl_mod_shadow_msg PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
  target_compile_definitions(ssl_mod_shadow_msg PRIVATE USE_SHADOW=1)

  target_include_directories(ssl_mod_shadow_msg
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/
  ${SEAMOCK_ROOT}/include)
sea_attach_bc(ssl_mod_shadow_msg)
set(LLVMIR_OPT ${SEA_PP})
llvmir_attach_opt_pass_target(TARGET ssl_mod_shadow_msg.opt.ir DEPENDS ssl_mod_shadow_msg.ir
  "--externalize-function=^ssl_*" "-externalize-functions-delete=false" "--externalize-fns")

add_library(ssl_mod_main_msg STATIC
  ${MBEDTLS_MOD2_DIR}/library/ssl_msg.c)

  target_compile_definitions(ssl_mod_main_msg PRIVATE MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
  target_compile_definitions(ssl_mod_main_msg PRIVATE USE_SHADOW=0)

  target_include_directories(ssl_mod_main_msg
  PRIVATE ${MBEDTLS_DIR}/include/
  ${MBEDTLS_DIR}/library/
  ${PROJECT_SOURCE_DIR}/seahorn/include/
  ${SEAMOCK_ROOT}/include)
sea_attach_bc(ssl_mod_main_msg)
set(LLVMIR_OPT ${SEA_PP})
llvmir_attach_opt_pass_target(TARGET ssl_mod_main_msg.opt.ir DEPENDS ssl_mod_main_msg.ir
  "--externalize-function=^ssl_*" "-externalize-functions-delete=false" "--externalize-fns")

