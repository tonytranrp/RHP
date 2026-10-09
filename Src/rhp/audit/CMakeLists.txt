# Layer 4: audit sinks (Rhp::audit) that write host events as JSON lines to a file or a stream.
rhp_add_module(audit
    HEADERS
        sinks.hpp
    SOURCES
        sinks.cpp
    DEPS
        Rhp::event
)
