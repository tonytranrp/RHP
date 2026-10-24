include_guard(GLOBAL)

# Generates <rhp/build_config.hpp>: how this RHP was built (RHP_ENABLE, the TLS backends, the target
# OS). Rhp::core carries it as a header of its own, so it is installed with the other headers; every
# public header that branches on these macros includes it (see cmake/build_config.hpp.in).
set(RHP_GENERATED_INCLUDE_DIR "${PROJECT_BINARY_DIR}/include")

set(RHP_BUILD_CONFIG_ENABLE 0)
set(RHP_BUILD_CONFIG_TLS_HAS_OPENSSL 0)
set(RHP_BUILD_CONFIG_TLS_HAS_MBEDTLS 0)
if(RHP_ENABLE)
    set(RHP_BUILD_CONFIG_ENABLE 1)
    if(RHP_TLS_HAS_OPENSSL)
        set(RHP_BUILD_CONFIG_TLS_HAS_OPENSSL 1)
    endif()
    if(RHP_TLS_HAS_MBEDTLS)
        set(RHP_BUILD_CONFIG_TLS_HAS_MBEDTLS 1)
    endif()
endif()

# A translation unit defining another platform's macro would pick that platform in platform/os.hpp.
set(RHP_BUILD_CONFIG_OTHER_PLATFORMS "")
foreach(other IN ITEMS WINDOWS LINUX MACOS IOS ANDROID)
    if(NOT other STREQUAL RHP_PLATFORM)
        string(APPEND RHP_BUILD_CONFIG_OTHER_PLATFORMS
            "#if defined(RHP_PLATFORM_${other})\n"
            "#error \"RHP: RHP_PLATFORM_${other} is defined, but this RHP was built for ${RHP_PLATFORM}\"\n"
            "#endif\n")
    endif()
endforeach()

configure_file("${PROJECT_SOURCE_DIR}/cmake/build_config.hpp.in" "${RHP_GENERATED_INCLUDE_DIR}/rhp/build_config.hpp" @ONLY NEWLINE_STYLE LF)
