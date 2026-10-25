include_guard(GLOBAL)

# rhp_use_shared_pch(<target> <lib|tests>)
#
# RHP_PCH: the standard headers nearly every RHP translation unit includes (plus Catch2's macros for
# the tests) compiled once per group and reused by every target in it (REUSE_FROM), instead of
# parsed again by each source file. Measured on a clean MSVC Debug build: -37% wall time, -56%
# together with RHP_UNITY_BUILD. A precompiled header per target would cost more than it saves (about
# 190 MB each) and none is used for <rhp/rhp.hpp> (what the targets include of RHP differs).
#
# The headers come in force-included: an #include a file forgets still compiles with RHP_PCH, so CI
# builds one configuration without it.
set(RHP_PCH_STD_HEADERS
    <algorithm> <array> <atomic> <chrono> <cstddef> <cstdint> <expected> <filesystem> <format>
    <functional> <map> <memory> <mutex> <optional> <span> <string> <string_view> <thread>
    <type_traits> <utility> <variant> <vector>)

function(rhp_use_shared_pch target group)
    if(NOT RHP_PCH)
        return()
    endif()
    set(pch rhp_pch_${group})
    if(NOT TARGET ${pch})
        # Written only when it changes, so a reconfigure doesn't rebuild the header.
        file(CONFIGURE OUTPUT "${CMAKE_BINARY_DIR}/${pch}.cpp" CONTENT "// RHP's shared precompiled header (${group}): cmake/RhpPch.cmake\n")
        add_library(${pch} OBJECT "${CMAKE_BINARY_DIR}/${pch}.cpp")
        set(headers ${RHP_PCH_STD_HEADERS})
        if(group STREQUAL "tests")
            target_link_libraries(${pch} PRIVATE Catch2::Catch2 Rhp::core)
            list(APPEND headers <catch2/catch_test_macros.hpp>)
        else()
            target_link_libraries(${pch} PRIVATE Rhp::core)
            rhp_apply_platform(${pch})
        endif()
        rhp_set_warnings(${pch})
        target_precompile_headers(${pch} PRIVATE ${headers})
        set_target_properties(${pch} PROPERTIES FOLDER "build")
    endif()
    target_precompile_headers(${target} REUSE_FROM ${pch})
endfunction()
