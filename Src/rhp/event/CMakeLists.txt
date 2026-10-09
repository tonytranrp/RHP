# Layer 3: what a host reports (Rhp::event): typed events, a thread-safe hub, scoped subscriptions,
# JSON lines. Pure C++ (built with RHP_ENABLE=OFF too).
rhp_add_module(event
    HEADERS
        events.hpp
        hub.hpp
    SOURCES
        events.cpp
    DEPS
        Rhp::core
)
