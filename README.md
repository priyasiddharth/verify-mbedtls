![os](https://img.shields.io/badge/os-linux-orange?logo=linux)
[![CI](https://github.com/priyasiddharth/verify-mbedtls/actions/workflows/main.yml/badge.svg)](https://github.com/priyasiddharth/verify-mbedtls/actions?query=workflow%3ACI)

This project aims to verify the mbedtls library using the Seahorn BMC engine
and the SeaMock mocking framework.

## HOWTO build and test the project
Replicate instructions in `docker/verify-mbedtls.dockerfile`
 
## HOWTO add a verification job

``` sh
scripts/add-job <component> <job> <SUT>
```

