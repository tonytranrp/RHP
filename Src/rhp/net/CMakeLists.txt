# Layer 3: transports. Asio is PRIVATE and only io_context.cpp and tcp/tcp.cpp include it. With
# RHP_ENABLE=OFF there is no network code: the headers stay (configs still name the transports),
# nothing is compiled and Asio is not fetched.
set(rhp_net_sources "")
set(rhp_net_private_deps "")
if(RHP_ENABLE)
    set(rhp_net_sources
        io_context.cpp
        loopback/loopback.cpp
        tcp/tcp.cpp
    )
    set(rhp_net_private_deps Rhp::asio)
endif()

rhp_add_module(net
    HEADERS
        endpoint.hpp
        io_context.hpp
        link.hpp
        loopback/loopback.hpp
        tcp/tcp.hpp
    SOURCES
        ${rhp_net_sources}
    DEPS
        Rhp::core
        Rhp::platform
    PRIVATE_DEPS
        ${rhp_net_private_deps}
)
