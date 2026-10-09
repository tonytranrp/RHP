# Layer 5: Rhp::client<Cfg>. Thin template over an engine compiled once in client.cpp. Never links
# Lua: a client only speaks the wire. RHP_ENABLE=OFF: every call reports kDisabled.
set(rhp_client_sources "")
if(RHP_ENABLE)
    set(rhp_client_sources client.cpp)
endif()

rhp_add_module(client
    HEADERS
        client.hpp
        detail/engine.hpp
    SOURCES
        ${rhp_client_sources}
    DEPS
        Rhp::config
        Rhp::session
)
