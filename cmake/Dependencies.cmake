include_guard(GLOBAL)

# Every third-party pin lives in this file. Stages add their dependencies here, never inline.
#   Stage 0: Catch2 (tests only)
#   Stage 1: Lua 5.5.1        Stage 3: Asio 1.38.2, Monocypher 4.0.3
#   Stage 4: replxx, CLI11    Stage 5: OpenSSL (the system's, >= 3.0), Mbed TLS 4.2.0
# MessagePack is RHP's own codec (Src/rhp/wire/codec), so msgpack-c is not a dependency.

# A pin always means the fetched copy, never a package found on the machine.
set(CPM_USE_LOCAL_PACKAGES OFF)
set(CPM_LOCAL_PACKAGES_ONLY OFF)

# std::jthread (Rhp::exec) and the network thread need the system's thread library.
find_package(Threads REQUIRED)

# Git dependencies are fetched by tag (shallow) and then checked against the commit the tag named
# when it was pinned: a tag moved upstream, or a cache directory that changed, fails the configure
# instead of building other code. A dependency replaced with CPM_<name>_SOURCE is not checked.
find_package(Git QUIET)
function(rhp_verify_git_pin name commit)
    set(dir "${${name}_SOURCE_DIR}")
    if(DEFINED CPM_${name}_SOURCE AND NOT CPM_${name}_SOURCE STREQUAL "")
        message(STATUS "RHP: ${name} comes from CPM_${name}_SOURCE; its pin is not checked")
        return()
    endif()
    if(NOT GIT_EXECUTABLE)
        message(WARNING "RHP: git was not found; ${name}'s pin (${commit}) is not checked")
        return()
    endif()
    if(NOT EXISTS "${dir}/.git")
        message(FATAL_ERROR "RHP: can't check ${name}'s pin: ${dir} is not a git checkout")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -c safe.directory=* -C "${dir}" rev-parse HEAD
        OUTPUT_VARIABLE head
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE failed
        ERROR_QUIET
    )
    if(failed OR NOT head STREQUAL commit)
        message(FATAL_ERROR "RHP: ${name} at ${dir} is '${head}', but its pin is ${commit} (cmake/Dependencies.cmake). Delete that directory to fetch it again; if the tag moved upstream, review the change before updating the pin. (A parent project that added ${name} first shares its copy: set CPM_${name}_SOURCE to use a copy of your own choosing.)")
    endif()
endfunction()

if(RHP_BUILD_TESTS)
    # Assertion macros without their own try/catch (an exception still fails the test): about a fifth
    # less compile time per assertion. Forced so that existing build trees pick it up too.
    set(CATCH_CONFIG_FAST_COMPILE ON CACHE BOOL "Catch2: no try/catch per assertion (set by RHP)" FORCE)
    CPMAddPackage(
        NAME Catch2
        GITHUB_REPOSITORY catchorg/Catch2
        GIT_TAG v3.16.1
        OPTIONS "CATCH_INSTALL_DOCS OFF" "CATCH_INSTALL_EXTRAS OFF"
        SYSTEM YES
    )
    rhp_verify_git_pin(Catch2 08092139210881f01a34e60c5f2fd6afa0ea4024)
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
    rhp_verify_git_pin(lua 7579fc9d7ed90240487251dfb69168f8e64e9294)
    include(RhpLua)

    # Networking (Rhp::net) and the PSK handshake + frame MAC (Rhp::security). Like Lua, only live
    # builds fetch them: RHP_ENABLE=OFF has no network code at all.
    CPMAddPackage(
        NAME asio
        GITHUB_REPOSITORY chriskohlhoff/asio
        GIT_TAG asio-1-38-2
        DOWNLOAD_ONLY YES
    )
    rhp_verify_git_pin(asio 8806a6803cde7054c3049d3666d3ec36786568c5)
    include(RhpAsio)

    CPMAddPackage(
        NAME monocypher
        GITHUB_REPOSITORY LoupVaillant/Monocypher
        GIT_TAG 4.0.3
        DOWNLOAD_ONLY YES
    )
    rhp_verify_git_pin(monocypher ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f)
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
    rhp_verify_git_pin(CLI11 cbd58a3696887b34c70949aef21a71735a0c2ad5)
    CPMAddPackage(
        NAME replxx
        GITHUB_REPOSITORY AmokHuginnsson/replxx
        GIT_TAG release-0.0.4
        DOWNLOAD_ONLY YES
    )
    rhp_verify_git_pin(replxx 2b248467112cbbc16f63fde38230fd7c7ffc55f1)
    include(RhpTools)
endif()
