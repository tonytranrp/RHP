# Layer 4: handshake, reliability and heartbeat over any transport. Knows transports, codecs and
# authenticators only through their abstract interfaces (net::link, wire::codec_ops,
# security::host_handshake / client_handshake), so it compiles once, not per config.
set(rhp_session_sources "")
if(RHP_ENABLE)
    set(rhp_session_sources session.cpp secure_link.cpp backoff.cpp)
endif()

rhp_add_module(session
    HEADERS
        backoff.hpp
        secure_link.hpp
        session.hpp
    SOURCES
        ${rhp_session_sources}
    DEPS
        Rhp::net
        Rhp::security
        Rhp::tls
        Rhp::wire
)
