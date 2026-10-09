include_guard(GLOBAL)

# Bootstraps CPM.cmake at a pinned release. The download is cached per CPM version,
# in CPM_SOURCE_CACHE when set, otherwise inside the build tree.
set(RHP_CPM_VERSION 0.42.3)

if(CPM_SOURCE_CACHE)
    set(_rhp_cpm_file "${CPM_SOURCE_CACHE}/cpm/CPM_${RHP_CPM_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
    set(_rhp_cpm_file "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${RHP_CPM_VERSION}.cmake")
else()
    set(_rhp_cpm_file "${CMAKE_BINARY_DIR}/cmake/CPM_${RHP_CPM_VERSION}.cmake")
endif()

if(NOT EXISTS "${_rhp_cpm_file}")
    message(STATUS "RHP: downloading CPM.cmake ${RHP_CPM_VERSION}")
    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${RHP_CPM_VERSION}/CPM.cmake"
        "${_rhp_cpm_file}"
        STATUS _rhp_cpm_status
    )
    list(GET _rhp_cpm_status 0 _rhp_cpm_code)
    if(NOT _rhp_cpm_code EQUAL 0)
        file(REMOVE "${_rhp_cpm_file}")
        message(FATAL_ERROR "RHP: failed to download CPM.cmake: ${_rhp_cpm_status}")
    endif()
endif()

include("${_rhp_cpm_file}")
