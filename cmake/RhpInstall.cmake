include_guard(GLOBAL)

# Install rules and the CMake package (RHP_INSTALL):
#
#   include/rhp/...                 every public header, plus the generated rhp/build_config.hpp
#   lib/rhp_<module>[d].lib|.a      RHP's archives (d: Debug)
#   lib/rhp/...                     the third-party archives RHP links (Lua, Monocypher, Mbed TLS)
#   lib/cmake/rhp/                  rhp-config.cmake: find_package(rhp CONFIG) -> Rhp::rhp, Rhp::<module>
#   share/doc/rhp/                  LICENSE, NOTICE, THIRD_PARTY_LICENSES.md, licenses/
#   bin/rhp-cli                     COMPONENT tools (when built)
#
# Third-party headers (lua.h, asio.hpp, monocypher.h, mbedtls/) are not installed: no public RHP
# header includes them.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(RHP_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/rhp" CACHE STRING "Where the rhp CMake package is installed, relative to the prefix")
mark_as_advanced(RHP_INSTALL_CMAKEDIR)

get_property(rhp_install_targets GLOBAL PROPERTY RHP_INSTALL_TARGETS)
foreach(target IN LISTS rhp_install_targets)
    set(file_sets "")
    get_target_property(header_sets ${target} INTERFACE_HEADER_SETS)
    foreach(set_name IN LISTS header_sets)
        list(APPEND file_sets FILE_SET ${set_name} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" COMPONENT development)
    endforeach()
    install(TARGETS ${target}
        EXPORT RhpTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT development
        ${file_sets}
    )
endforeach()

get_property(rhp_third_party_targets GLOBAL PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS)
if(rhp_third_party_targets)
    install(TARGETS ${rhp_third_party_targets}
        EXPORT RhpTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/rhp" COMPONENT development
    )
endif()

install(EXPORT RhpTargets
    NAMESPACE Rhp::
    FILE RhpTargets.cmake
    DESTINATION "${RHP_INSTALL_CMAKEDIR}"
    COMPONENT development
)

# What the package reports about itself (rhp_STAGE, rhp_PROTOCOL_REVISION, ...).
file(STRINGS "${PROJECT_SOURCE_DIR}/Src/rhp/wire/ops.hpp" rhp_revision_line REGEX "kProtocolRevision = [0-9]+")
if(NOT rhp_revision_line MATCHES "kProtocolRevision = ([0-9]+)")
    message(FATAL_ERROR "RHP: can't read kProtocolRevision from Src/rhp/wire/ops.hpp")
endif()
set(RHP_PROTOCOL_REVISION ${CMAKE_MATCH_1})

set(RHP_PACKAGE_ANDROID_ABI "")
if(RHP_PLATFORM STREQUAL "ANDROID")
    set(RHP_PACKAGE_ANDROID_ABI "${CMAKE_ANDROID_ARCH_ABI}")
endif()
set(RHP_PACKAGE_MSVC_ABI OFF)
if(MSVC)
    set(RHP_PACKAGE_MSVC_ABI ON)
endif()

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/rhp-config.cmake.in"
    "${PROJECT_BINARY_DIR}/package/rhp-config.cmake"
    INSTALL_DESTINATION "${RHP_INSTALL_CMAKEDIR}"
    NO_SET_AND_CHECK_MACRO
)
configure_file("${PROJECT_SOURCE_DIR}/cmake/rhp-config-version.cmake.in" "${PROJECT_BINARY_DIR}/package/rhp-config-version.cmake" @ONLY)
install(FILES
    "${PROJECT_BINARY_DIR}/package/rhp-config.cmake"
    "${PROJECT_BINARY_DIR}/package/rhp-config-version.cmake"
    "${PROJECT_SOURCE_DIR}/cmake/RhpLuaTests.cmake"
    DESTINATION "${RHP_INSTALL_CMAKEDIR}"
    COMPONENT development
)

include(RhpLicenses)
