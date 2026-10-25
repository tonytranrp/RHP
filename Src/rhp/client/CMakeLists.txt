# Layer 5: Rhp::client<Cfg> and Rhp::fleet<Cfg>. Thin templates over engines compiled once in
# client.cpp and fleet.cpp. Never links Lua: a client only speaks the wire. RHP_ENABLE=OFF: every
# call reports kDisabled.
set(rhp_client_sources "")
if(RHP_ENABLE)
    set(rhp_client_sources client.cpp fleet.cpp rollout.cpp)
endif()

rhp_add_module(client
    HEADERS
        client.hpp
        fleet.hpp
        detail/engine.hpp
        detail/fleet_engine.hpp
        pending.hpp
        rollout.hpp
    SOURCES
        ${rhp_client_sources}
    DEPS
        Rhp::config
        Rhp::session
)
