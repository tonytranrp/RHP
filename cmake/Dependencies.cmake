include_guard(GLOBAL)

# Every third-party pin lives in this file. Stages add their dependencies here, never inline.
#   Stage 0: Catch2 (tests only)
#   Stage 1: Lua 5.5.1        Stage 3: Asio 1.38.2, Monocypher 4.0.3
#   Stage 4: replxx, CLI11    Stage 5: OpenSSL (the system's, >= 3.0), Mbed TLS 4.2.0
# MessagePack is RHP's own codec (Src/rhp/wire/codec), so msgpack-c is not a dependency.

if(RHP_BUILD_TESTS)
    CPMAddPackage(
        NAME Catch2
        GITHUB_REPOSITORY catchorg/Catch2
        GIT_TAG v3.16.1
        OPTIONS "CATCH_INSTALL_DOCS OFF" "CATCH_INSTALL_EXTRAS OFF"
        SYSTEM YES
    )
    list(APPEND CMAKE_MODULE_PATH "${Catch2_SOURCE_DIR}/extras")
endif()

# Lua is only needed for the live engine; RHP_ENABLE=OFF builds never fetch or link it.
if(RHP_ENABLE)
    CPMAddPackage(
        NAME lua
        GITHUB_REPOSITORY lua/lua
        GIT_TAG v5.5.1
        DOWNLOAD_ONLY YES
    )
    include(RhpLua)

    # Networking (Rhp::net) and the PSK handshake + frame MAC (Rhp::security). Like Lua, only live
    # builds fetch them: RHP_ENABLE=OFF has no network code at all.
    CPMAddPackage(
        NAME asio
        GITHUB_REPOSITORY chriskohlhoff/asio
        GIT_TAG asio-1-38-2
        DOWNLOAD_ONLY YES
    )
    include(RhpAsio)

    CPMAddPackage(
        NAME monocypher
        GITHUB_REPOSITORY LoupVaillant/Monocypher
        GIT_TAG 4.0.3
        DOWNLOAD_ONLY YES
    )
    include(RhpMonocypher)

    # TLS (Rhp::security::tls). OpenSSL is never fetched or built (that needs Perl and NASM): the
    # system's is used when CMake finds it, on desktop only. Mbed TLS comes from its release tarball,
    # which ships its generated files, so no Python is needed.
    set(RHP_TLS_HAS_OPENSSL OFF)
    set(RHP_TLS_HAS_MBEDTLS OFF)
    if(RHP_WITH_TLS)
        if(NOT RHP_TLS_OPENSSL STREQUAL "OFF" AND NOT RHP_PLATFORM STREQUAL "IOS" AND NOT RHP_PLATFORM STREQUAL "ANDROID")
            if(RHP_TLS_OPENSSL STREQUAL "ON")
                find_package(OpenSSL 3.0 REQUIRED)
            else()
                find_package(OpenSSL 3.0 QUIET)
            endif()
            if(OpenSSL_FOUND OR OPENSSL_FOUND)
                set(RHP_TLS_HAS_OPENSSL ON)
            endif()
        endif()
        if(RHP_TLS_MBEDTLS)
            CPMAddPackage(
                NAME mbedtls
                URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.2.0/mbedtls-4.2.0.tar.bz2
                URL_HASH SHA256=2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea
                VERSION 4.2.0
                DOWNLOAD_ONLY YES
            )
            include(RhpMbedtls)
            set(RHP_TLS_HAS_MBEDTLS ON)
        endif()
    endif()
    message(STATUS "RHP: TLS backends: OpenSSL ${RHP_TLS_HAS_OPENSSL}, Mbed TLS ${RHP_TLS_HAS_MBEDTLS}")
endif()

# rhp-cli (Tools/): line editing and argument parsing. Desktop tools only, never linked into RHP.
if(RHP_BUILD_TOOLS AND RHP_ENABLE)
    CPMAddPackage(
        NAME CLI11
        GITHUB_REPOSITORY CLIUtils/CLI11
        GIT_TAG v2.7.2
        DOWNLOAD_ONLY YES
    )
    CPMAddPackage(
        NAME replxx
        GITHUB_REPOSITORY AmokHuginnsson/replxx
        GIT_TAG release-0.0.4
        DOWNLOAD_ONLY YES
    )
    include(RhpTools)
endif()
