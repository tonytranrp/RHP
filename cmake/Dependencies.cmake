include_guard(GLOBAL)

# Every third-party pin lives in this file. Stages add their dependencies here, never inline.
#   Stage 0: Catch2 (tests only)
#   Stage 1: Lua 5.5          Stage 3: Asio, msgpack-c
#   Stage 4: Monocypher, replxx, CLI11
#   Stage 5: OpenSSL / mbedTLS

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
