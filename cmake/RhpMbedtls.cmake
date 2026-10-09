include_guard(GLOBAL)

# Rhp::mbedtls: Mbed TLS 4.2 (with TF-PSA-Crypto) as a subproject, static, without its programs,
# tests or install rules. Only Rhp::tls links it, PRIVATE, and only mbedtls.cpp includes its
# headers. Its C sources get the global sanitizer flags like everything else.
if(NOT DEFINED mbedtls_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpMbedtls after CPMAddPackage(NAME mbedtls ...)")
endif()

enable_language(C)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "" FORCE)
add_subdirectory("${mbedtls_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/_deps/mbedtls-build" EXCLUDE_FROM_ALL SYSTEM)

add_library(rhp_mbedtls INTERFACE)
add_library(Rhp::mbedtls ALIAS rhp_mbedtls)
target_link_libraries(rhp_mbedtls INTERFACE MbedTLS::mbedtls)
