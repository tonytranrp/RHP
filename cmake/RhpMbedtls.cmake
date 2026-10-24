include_guard(GLOBAL)

# Rhp::mbedtls: Mbed TLS 4.2 (with TF-PSA-Crypto) as a subproject, static, without its programs,
# tests or install rules. Only Rhp::tls links it, PRIVATE, and only mbedtls.cpp includes its
# headers. Its C sources get the global sanitizer flags like everything else.
if(NOT DEFINED mbedtls_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpMbedtls after CPMAddPackage(NAME mbedtls ...)")
endif()

enable_language(C)

# Mbed TLS's switches are option()s: set as normal variables inside a block (CMP0077 NEW), they
# configure this subproject without writing cache entries a parent project (or its own Mbed TLS)
# would see. The build directory is RHP's, so it never collides with a parent's Mbed TLS either.
block()
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(CMAKE_WARN_DEPRECATED OFF) # upstream still declares cmake_minimum_required(3.5.1)
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

add_library(rhp_mbedtls INTERFACE)
add_library(Rhp::mbedtls ALIAS rhp_mbedtls)
target_link_libraries(rhp_mbedtls INTERFACE MbedTLS::mbedtls)
set_target_properties(rhp_mbedtls PROPERTIES EXPORT_NAME mbedtls)
set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS rhp_mbedtls)

# The upstream archives an installed RHP links (mbedtls -> mbedx509 -> tfpsacrypto), exported under
# names that can't collide with a separately installed Mbed TLS package.
foreach(alias IN ITEMS MbedTLS::mbedtls MbedTLS::mbedx509 TF-PSA-Crypto::tfpsacrypto)
    get_target_property(real ${alias} ALIASED_TARGET)
    if(NOT real)
        message(FATAL_ERROR "RHP: Mbed TLS no longer defines ${alias}; update cmake/RhpMbedtls.cmake")
    endif()
    string(REGEX REPLACE "^.*::" "" short "${alias}")
    set_target_properties(${real} PROPERTIES EXPORT_NAME "mbedtls_${short}" FOLDER "third_party")
    set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS ${real})
endforeach()
