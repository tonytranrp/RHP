include_guard(GLOBAL)

# rhp_use_shared_pch(<target> <lib|tests|apps|asio>)
#
# RHP_PCH: the standard headers nearly every RHP translation unit includes (plus Catch2's macros for
# the tests) compiled once per group and reused by every target in it (REUSE_FROM), instead of
# parsed again by each source file. Measured on a clean MSVC Debug build: -37% wall time, -56%
# together with RHP_UNITY_BUILD (before RHP's core headers joined it). A precompiled header per target would cost more than it saves (about
# 190 MB each) and none is used for <rhp/rhp.hpp> (what the targets include of RHP differs).
#
# The headers come in force-included: an #include a file forgets still compiles with RHP_PCH, so CI
# builds one configuration without it.
set(RHP_PCH_STD_HEADERS
    <algorithm> <array> <atomic> <chrono> <cstddef> <cstdint> <expected> <filesystem> <format>
    <functional> <map> <memory> <mutex> <optional> <span> <string> <string_view> <thread>
    <type_traits> <utility> <variant> <vector>)

# RHP's own core and utils headers: most translation units include them, they change rarely, and
# none branches on RHP_ENABLE or the platform. Measured on MSVC Debug over 24 representative sources:
# -27% compile time (the standard headers alone: -1%).
set(RHP_PCH_RHP_HEADERS
    <rhp/core/error.hpp> <rhp/core/result.hpp> <rhp/core/role.hpp> <rhp/core/ids.hpp> <rhp/core/value.hpp>
    <rhp/core/convert.hpp> <rhp/core/async.hpp> <rhp/core/limits.hpp> <rhp/core/subscription.hpp>
    <rhp/core/listener_table.hpp> <rhp/utils/type_list.hpp> <rhp/utils/fixed_string.hpp>
    <rhp/utils/function_traits.hpp> <rhp/utils/byte_buffer.hpp> <rhp/utils/scope_guard.hpp>)

# Asio's headers most of rhp_net's Asio translation units include (rhp_net_asio): parsing them and
# instantiating their executor machinery was 1.6-2.6 s per file.
set(RHP_PCH_ASIO_HEADERS
    <asio/io_context.hpp> <asio/ip/address.hpp> <asio/steady_timer.hpp> <asio/post.hpp> <asio/write.hpp>
    <asio/ip/udp.hpp> <asio/ip/tcp.hpp> <asio/connect.hpp>)

function(rhp_use_shared_pch target group)
    if(NOT RHP_PCH)
        return()
    endif()
    set(pch rhp_pch_${group})
    if(NOT TARGET ${pch})
        # Written only when it changes, so a reconfigure doesn't rebuild the header.
        file(CONFIGURE OUTPUT "${CMAKE_BINARY_DIR}/${pch}.cpp" CONTENT "// RHP's shared precompiled header (${group}): cmake/RhpPch.cmake\n")
        add_library(${pch} OBJECT "${CMAKE_BINARY_DIR}/${pch}.cpp")
        set(headers ${RHP_PCH_STD_HEADERS} ${RHP_PCH_RHP_HEADERS})
        if(group STREQUAL "tests" OR group STREQUAL "apps")
            # tests: the test suites; apps: the examples, rhp-cli and the fuzz replay drivers. Both
            # are executables without the library's platform macros (rhp_apply_platform), which a
            # precompiled header must match.
            target_link_libraries(${pch} PRIVATE Rhp::core)
            if(group STREQUAL "tests")
                target_link_libraries(${pch} PRIVATE Catch2::Catch2)
                list(APPEND headers <catch2/catch_test_macros.hpp>)
            endif()
            # Executables compile position-independent as executables (-fPIE), and Clang refuses a
            # header precompiled as library code (-fPIC).
            if(NOT MSVC AND CMAKE_POSITION_INDEPENDENT_CODE AND CMAKE_CXX_COMPILE_OPTIONS_PIE)
                set_target_properties(${pch} PROPERTIES POSITION_INDEPENDENT_CODE OFF)
                target_compile_options(${pch} PRIVATE ${CMAKE_CXX_COMPILE_OPTIONS_PIE})
            endif()
        elseif(group STREQUAL "asio")
            # Asio's own macros come with the target, so they match the sources using it.
            target_link_libraries(${pch} PRIVATE Rhp::core "$<BUILD_INTERFACE:Rhp::asio>")
            list(APPEND headers ${RHP_PCH_ASIO_HEADERS})
            rhp_apply_platform(${pch})
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
