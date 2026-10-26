include_guard(GLOBAL)

# rhp_add_module(<name>
#     HEADERS <files...>      relative to the module folder, included (and installed) as <rhp/<name>/...>
#     GENERATED_HEADERS <files...>  relative to RHP_GENERATED_INCLUDE_DIR (configured by CMake), installed too
#     SOURCES <files...>      optional; without sources the module is an INTERFACE library
#     DEPS    <targets...>    public dependencies on lower layers (Rhp::utils, Rhp::core, ...)
#     PRIVATE_DEPS <targets...>)
#
# Creates target rhp_<name> with alias Rhp::<name> (exported as Rhp::<name> too). Header file sets
# are rooted at Src/ so every header is included as <rhp/<name>/<file>.hpp>.
function(rhp_add_module name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "HEADERS;GENERATED_HEADERS;SOURCES;DEPS;PRIVATE_DEPS")

    set(target rhp_${name})
    if(arg_SOURCES)
        add_library(${target} STATIC)
        target_sources(${target} PRIVATE ${arg_SOURCES})
        set(scope PUBLIC)
        rhp_set_warnings(${target})
    else()
        if(arg_PRIVATE_DEPS)
            message(FATAL_ERROR "RHP: module '${name}' has no sources, so it can't have PRIVATE_DEPS (${arg_PRIVATE_DEPS})")
        endif()
        add_library(${target} INTERFACE)
        set(scope INTERFACE)
    endif()
    add_library(Rhp::${name} ALIAS ${target})

    target_sources(${target} ${scope}
        FILE_SET HEADERS
        BASE_DIRS "${PROJECT_SOURCE_DIR}/Src"
        FILES ${arg_HEADERS}
    )
    if(arg_GENERATED_HEADERS)
        list(TRANSFORM arg_GENERATED_HEADERS PREPEND "${RHP_GENERATED_INCLUDE_DIR}/")
        target_sources(${target} ${scope}
            FILE_SET generated
            TYPE HEADERS
            BASE_DIRS "${RHP_GENERATED_INCLUDE_DIR}"
            FILES ${arg_GENERATED_HEADERS}
        )
    endif()
    target_compile_features(${target} ${scope} cxx_std_23)
    if(arg_DEPS)
        target_link_libraries(${target} ${scope} ${arg_DEPS})
    endif()
    if(arg_PRIVATE_DEPS)
        target_link_libraries(${target} PRIVATE ${arg_PRIVATE_DEPS})
    endif()
    if(arg_SOURCES)
        rhp_apply_platform(${target})
    else()
        target_compile_definitions(${target} INTERFACE RHP_PLATFORM_${RHP_PLATFORM}=1)
    endif()
    if(RHP_ENABLE)
        target_compile_definitions(${target} ${scope} RHP_ENABLE=1)
    else()
        target_compile_definitions(${target} ${scope} RHP_ENABLE=0)
    endif()
    # The shared precompiled header is built on Rhp::core: the modules below it compile without.
    # net's Asio translation units compile apart from it (rhp_net_asio, Src/rhp/net/CMakeLists.txt).
    if(arg_SOURCES AND NOT name STREQUAL "utils" AND NOT name STREQUAL "core")
        rhp_use_shared_pch(${target} lib)
    endif()
    set_target_properties(${target} PROPERTIES EXPORT_NAME ${name} FOLDER "rhp")
    set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_TARGETS ${target})
endfunction()
