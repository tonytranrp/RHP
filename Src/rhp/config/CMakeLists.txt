# Layer 5: Rhp::config<> — the type-level chain naming a host's or client's policies. Header-only.
rhp_add_module(config
    HEADERS
        config.hpp
    DEPS
        Rhp::net
        Rhp::security
        Rhp::tls
        Rhp::exec
        Rhp::wire
)
