include_guard(GLOBAL)

# Rhp::mbedtls: Mbed TLS 4.2 (with TF-PSA-Crypto) as a subproject, static, without its programs,
# tests or install rules. Only Rhp::tls links it, PRIVATE, and only mbedtls.cpp includes its
# headers. Its C sources get the global sanitizer flags like everything else.
if(NOT DEFINED mbedtls_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpMbedtls after CPMAddPackage(NAME mbedtls ...)")
endif()

enable_language(C)

# Keep out of a parent project's way, which may build its own Mbed TLS:
# - Mbed TLS's switches are option()s, set here as normal variables inside a block (CMP0077 NEW), so
#   they configure this copy without cache entries anyone else sees.
# - Its targets get the prefix rhp_mbedtls_ (rhp_mbedtls_mbedtls, ...), so they can't collide with
#   the parent's mbedtls / mbedx509 / tfpsacrypto.
# - It still writes a few set(... CACHE) entries of its own; CMP0126 NEW keeps our values in this
#   scope, and the entries it created are removed afterwards (its *_CONFIG_FILE knobs stay, so a
#   build can still pick an Mbed TLS configuration).
# - It builds under RHP's binary directory.
set(rhp_mbedtls_cache_vars TF_PSA_CRYPTO_TARGET_PREFIX TF_PSA_CRYPTO_FATAL_WARNINGS USE_STATIC_TF_PSA_CRYPTO_LIBRARY USE_SHARED_TF_PSA_CRYPTO_LIBRARY
    INSTALL_MBEDTLS_HEADERS INSTALL_TF_PSA_CRYPTO_HEADERS TF_PSA_CRYPTO_TEST_DRIVER)
set(rhp_mbedtls_created_cache "")
foreach(var IN LISTS rhp_mbedtls_cache_vars)
    if(NOT DEFINED CACHE{${var}})
        list(APPEND rhp_mbedtls_created_cache ${var})
    endif()
endforeach()

block()
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(CMAKE_POLICY_DEFAULT_CMP0126 NEW)
    set(CMAKE_POLICY_VERSION_MINIMUM 3.10) # upstream still declares cmake_minimum_required(3.5.1)
    set(MBEDTLS_TARGET_PREFIX rhp_mbedtls_)
    set(TF_PSA_CRYPTO_TARGET_PREFIX rhp_mbedtls_)
    set(ENABLE_PROGRAMS OFF)
    set(ENABLE_TESTING OFF)
    set(MBEDTLS_FATAL_WARNINGS OFF)
    set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF)
    set(GEN_FILES OFF)
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON)
    set(USE_STATIC_MBEDTLS_LIBRARY ON)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF)
    set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON)
    set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF)
    add_subdirectory("${mbedtls_SOURCE_DIR}" "${PROJECT_BINARY_DIR}/_deps/rhp-mbedtls-build" EXCLUDE_FROM_ALL SYSTEM)
endblock()

foreach(var IN LISTS rhp_mbedtls_created_cache)
    unset(${var} CACHE)
endforeach()

add_library(rhp_mbedtls INTERFACE)
add_library(Rhp::mbedtls ALIAS rhp_mbedtls)
target_link_libraries(rhp_mbedtls INTERFACE MbedTLS::rhp_mbedtls_mbedtls)
set_target_properties(rhp_mbedtls PROPERTIES EXPORT_NAME mbedtls)
set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS rhp_mbedtls)

# The upstream archives an installed RHP links (mbedtls -> mbedx509 -> tfpsacrypto), exported as
# Rhp::mbedtls_tls / _x509 / _crypto.
foreach(pair IN ITEMS "MbedTLS::rhp_mbedtls_mbedtls|tls" "MbedTLS::rhp_mbedtls_mbedx509|x509" "TF-PSA-Crypto::rhp_mbedtls_tfpsacrypto|crypto")
    string(REPLACE "|" ";" pair "${pair}")
    list(GET pair 0 alias)
    list(GET pair 1 role)
    if(NOT TARGET ${alias})
        message(FATAL_ERROR "RHP: Mbed TLS no longer defines ${alias}; update cmake/RhpMbedtls.cmake")
    endif()
    get_target_property(real ${alias} ALIASED_TARGET)
    set_target_properties(${real} PROPERTIES EXPORT_NAME "mbedtls_${role}" FOLDER "third_party")
    set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS ${real})
endforeach()
