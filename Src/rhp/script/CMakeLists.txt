# Layer 3: the script engine. Lua is a PRIVATE dependency and only puc_lua/*.cpp include lua.h.
# With RHP_ENABLE=OFF the sandbox compiles to an inert stub and Lua is neither fetched nor linked;
# the lib DSL, ledger and patch points (direct calls) still build.
set(rhp_script_sources
    event_registry.cpp
    ledger.cpp
    patch_registry.cpp
    stubs.cpp
)
set(rhp_script_private_deps "")
if(RHP_ENABLE)
    list(APPEND rhp_script_sources
        puc_lua/async.cpp
        puc_lua/buffer.cpp
        puc_lua/lib_proxy.cpp
        puc_lua/sandbox.cpp
        puc_lua/small_alloc.cpp
        puc_lua/schedule.cpp
        puc_lua/script_events.cpp
        puc_lua/stack.cpp
        puc_lua/debug.cpp
        puc_lua/profile.cpp
        puc_lua/tasks.cpp
        puc_lua/testing.cpp
        puc_lua/lua_internals.cpp
        puc_lua/tools.cpp
        puc_lua/view_journal.cpp
        puc_lua/views.cpp
    )
    list(APPEND rhp_script_private_deps Rhp::lua)
else()
    list(APPEND rhp_script_sources sandbox_disabled.cpp)
endif()

rhp_add_module(script
    HEADERS
        api.hpp
        ledger.hpp
        lib.hpp
        lua_event.hpp
        marshal.hpp
        patch_point.hpp
        sandbox.hpp
        stack.hpp
        debug.hpp
        stubs.hpp
        testing.hpp
        tunables.hpp
        views.hpp
        detail/call_guard.hpp
        detail/context.hpp
        detail/event_registry.hpp
        detail/lib_builder.hpp
        detail/lib_traits.hpp
        detail/patch_layers.hpp
        detail/patch_registry.hpp
        detail/var_layers.hpp
    SOURCES
        ${rhp_script_sources}
    DEPS
        Rhp::core
    PRIVATE_DEPS
        ${rhp_script_private_deps}
)

# RHP_UNITY_BUILD: these keep their own translation unit (file-local helpers named like ones in the
# sources batched with them).
set_source_files_properties(patch_registry.cpp puc_lua/debug.cpp puc_lua/profile.cpp puc_lua/testing.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
