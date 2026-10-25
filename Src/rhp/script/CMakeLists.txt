# Layer 3: the script engine. Lua is a PRIVATE dependency and only puc_lua/*.cpp include lua.h.
# With RHP_ENABLE=OFF the sandbox compiles to an inert stub and Lua is neither fetched nor linked;
# the lib DSL, ledger and patch points (direct calls) still build.
set(rhp_script_sources
    event_registry.cpp
    ledger.cpp
    patch_registry.cpp
)
set(rhp_script_private_deps "")
if(RHP_ENABLE)
    list(APPEND rhp_script_sources
        puc_lua/async.cpp
        puc_lua/lib_proxy.cpp
        puc_lua/sandbox.cpp
        puc_lua/schedule.cpp
        puc_lua/script_events.cpp
        puc_lua/stack.cpp
        puc_lua/tasks.cpp
    )
    list(APPEND rhp_script_private_deps Rhp::lua)
else()
    list(APPEND rhp_script_sources sandbox_disabled.cpp)
endif()

rhp_add_module(script
    HEADERS
        ledger.hpp
        lib.hpp
        lua_event.hpp
        marshal.hpp
        patch_point.hpp
        sandbox.hpp
        stack.hpp
        stubs.hpp
        detail/context.hpp
        detail/event_registry.hpp
        detail/lib_builder.hpp
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
