# Layer 3: transports and discovery. Asio is PRIVATE to backend translation units. With
# RHP_ENABLE=OFF there is no network code: the headers stay (configs still name the transports),
# nothing is compiled and Asio is not fetched.
set(rhp_net_sources "")
set(rhp_net_private_deps "")
if(RHP_ENABLE)
    set(rhp_net_sources
        io_context.cpp
        loopback/loopback.cpp
        tcp/tcp.cpp
        detail/http.cpp
        detail/http_connection.cpp
        mdns/metadata.cpp
        mdns/dns.cpp
        mdns/wire.cpp
        mdns/native.cpp
        websocket/detail/protocol.cpp
        websocket/websocket.cpp
        local/local.cpp
        udp_reliable/detail/packet.cpp
        udp_reliable/udp_reliable.cpp
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
        detail/http.hpp
        detail/http_connection.hpp
        discovery.hpp
        mdns/mdns.hpp
        mdns/detail/metadata.hpp
        mdns/detail/dns.hpp
        websocket/websocket.hpp
        websocket/detail/protocol.hpp
        local/local.hpp
        udp_reliable/udp_reliable.hpp
        udp_reliable/detail/packet.hpp
    SOURCES
        ${rhp_net_sources}
    DEPS
        Rhp::core
        Rhp::platform
    PRIVATE_DEPS
        ${rhp_net_private_deps}
)

if(RHP_ENABLE AND RHP_PLATFORM STREQUAL "WINDOWS")
    target_link_libraries(rhp_net PRIVATE dnsapi advapi32 iphlpapi)
elseif(RHP_ENABLE AND (RHP_PLATFORM STREQUAL "MACOS" OR RHP_PLATFORM STREQUAL "IOS"))
    target_link_libraries(rhp_net PRIVATE dns_sd)
endif()
