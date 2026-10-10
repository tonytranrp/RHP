# Layer 5: Rhp::host<Cfg>. The template is a thin shell; the engine (sessions, identities,
# sandboxes, routing) is compiled once in host.cpp. RHP_ENABLE=OFF: the shell is inert, no engine.
set(rhp_host_sources "")
if(RHP_ENABLE)
    set(rhp_host_sources host.cpp gateway.cpp)
endif()

rhp_add_module(host
    HEADERS
        host.hpp
        detail/engine.hpp
    SOURCES
        ${rhp_host_sources}
    DEPS
        Rhp::config
        Rhp::session
        Rhp::script
        Rhp::event
)
