cmake_minimum_required(VERSION 3.18.4)
project(verifyTrusty C CXX)

set (CMAKE_CXX_STANDARD 17)  # for seamock
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/llvmir)
include(LLVMIRUtil)
include(CTest)

#boost version >= 1.71 because of https: // github.com/boostorg/hana/issues/446
set(Boost_USE_STATIC_LIBS ${SEAHORN_STATIC_EXE})
find_package(Boost 1.71 REQUIRED)
if (Boost_FOUND)
  include_directories (${Boost_INCLUDE_DIRS})
  if(NOT LLVM_ENABLE_EH)
    add_definitions(-DBOOST_NO_EXCEPTIONS)
  endif()
endif ()

#Enable CTest
enable_testing()

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR )
  message (FATAL_ERROR
    "In-source builds are not allowed. Please clean your source tree and try again.")
endif()

#Default is release with debug info
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
    "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

set(SEAHORN_ROOT "/usr" CACHE PATH "Path to SeaHorn installation")
set(SEA_LINK "llvm-link" CACHE STRING "Path to llvm-link")
set(LLVMIR_LINK ${SEA_LINK})
set(SEA_OPT "${SEAHORN_ROOT}/bin/seaopt" CACHE STRING  "Path to seaopt binary")
set(SEA_PP "${SEAHORN_ROOT}/bin/seapp" CACHE STRING  "Path to seapp binary")
set(LLVMIR_OPT ${SEA_OPT})
set(CPPSTDLIB "libc++" CACHE STRING "C++ std library to use")

set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls)
set(MBEDTLS_MOD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_mod)
set(SEAMOCK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/seamock/src)

set(SEA_LIB ${CMAKE_CURRENT_SOURCE_DIR}/seahorn/lib)

configure_file(verify.py.in verify @ONLY)
set(VERIFY_CMD ${CMAKE_CURRENT_BINARY_DIR}/verify)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR}/seahorn/include/
                           ${SEAHORN_ROOT}/include)             
add_subdirectory(seahorn)
