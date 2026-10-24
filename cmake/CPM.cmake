include_guard(GLOBAL)

# Bootstraps CPM.cmake at a pinned release, verified by SHA-256 on download and again on every
# configure (a cached copy that changed is fetched anew). The download is cached per CPM version,
# in CPM_SOURCE_CACHE when set, otherwise inside the build tree.
set(RHP_CPM_VERSION 0.42.3)
set(RHP_CPM_SHA256 a609e875fd532b067174250f6abbc3dac22fe2d64869783fb1e80bda1625c844)

if(CPM_SOURCE_CACHE)
    set(_rhp_cpm_file "${CPM_SOURCE_CACHE}/cpm/CPM_${RHP_CPM_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
    set(_rhp_cpm_file "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${RHP_CPM_VERSION}.cmake")
else()
    set(_rhp_cpm_file "${CMAKE_BINARY_DIR}/cmake/CPM_${RHP_CPM_VERSION}.cmake")
endif()

if(EXISTS "${_rhp_cpm_file}")
    file(SHA256 "${_rhp_cpm_file}" _rhp_cpm_hash)
    if(NOT _rhp_cpm_hash STREQUAL RHP_CPM_SHA256)
        message(STATUS "RHP: the cached CPM.cmake ${RHP_CPM_VERSION} doesn't match its pin; downloading it again")
        file(REMOVE "${_rhp_cpm_file}")
    endif()
endif()

if(NOT EXISTS "${_rhp_cpm_file}")
    message(STATUS "RHP: downloading CPM.cmake ${RHP_CPM_VERSION}")
    # Downloaded beside the target and renamed once verified, so an interrupted or concurrent
    # configure never leaves a partial file under the cached name.
    string(RANDOM LENGTH 8 _rhp_cpm_tag)
    set(_rhp_cpm_partial "${_rhp_cpm_file}.${_rhp_cpm_tag}.download")
    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${RHP_CPM_VERSION}/CPM.cmake"
        "${_rhp_cpm_partial}"
        EXPECTED_HASH SHA256=${RHP_CPM_SHA256}
        TLS_VERIFY ON
        STATUS _rhp_cpm_status
    )
    list(GET _rhp_cpm_status 0 _rhp_cpm_code)
    if(NOT _rhp_cpm_code EQUAL 0)
        file(REMOVE "${_rhp_cpm_partial}")
        message(FATAL_ERROR "RHP: failed to download CPM.cmake: ${_rhp_cpm_status}")
    endif()
    file(RENAME "${_rhp_cpm_partial}" "${_rhp_cpm_file}")
endif()

include("${_rhp_cpm_file}")
