# Layer 4: Rhp::test, the test engine for Lua scripts (offline, against a program's API). The Lua
# side of the framework lives in lua/*.lua and is embedded at configure time (cmake/RhpEmbed.cmake).
include(RhpEmbed)

set(rhp_test_lua
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/core.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/format.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/assert.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/spy.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/test.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/expect.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/property.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/fakes.lua"
)
set(rhp_test_embedded "${CMAKE_CURRENT_BINARY_DIR}/framework_sources.cpp")
rhp_embed_text("${rhp_test_embedded}"
    NAMESPACE Rhp::test::detail
    FUNCTION framework_sources
    PREFIX "rhp.test/"
    HEADER rhp/test/detail/framework.hpp
    FILES ${rhp_test_lua}
)

rhp_add_module(test
    HEADERS
        cli.hpp
        fake.hpp
        fake_registry.hpp
        options.hpp
        report.hpp
        reporter.hpp
        runner.hpp
        test.hpp
        detail/framework.hpp
    SOURCES
        cli.cpp
        detail/coverage.cpp
        detail/fuzz_corpus.cpp
        detail/snapshots.cpp
        fake_registry.cpp
        options.cpp
        reporters.cpp
        runner.cpp
        "${rhp_test_embedded}"
    DEPS
        Rhp::script
        Rhp::platform
        Rhp::core
)

# RHP_UNITY_BUILD: these keep their own translation unit (file-local helpers named like ones in the
# sources batched with them).
set_source_files_properties(runner.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
