add_definitions(
    -DMBEDTLS_SSL_IN_CONTENT_LEN = 2048
  )

add_subdirectory(env)
add_subdirectory(unit_proof)
