# Layer 2: frames, the payload codec and message schemas. Pure C++ with no dependencies, so it
# builds (and is tested) with RHP_ENABLE=OFF too.
rhp_add_module(wire
    HEADERS
        codec.hpp
        codec/msgpack.hpp
        frame.hpp
        messages.hpp
        ops.hpp
    SOURCES
        codec/msgpack.cpp
        frame.cpp
        messages.cpp
    DEPS
        Rhp::core
)
