# Layer 3: transports and discovery. Asio is PRIVATE to backend translation units. With
# RHP_ENABLE=OFF there is no network code: the headers stay (configs still name the transports),
# nothing is compiled and Asio is not fetched.
set(rhp_net_sources "")
set(rhp_net_asio_sources "")
set(rhp_net_private_deps "")
if(RHP_ENABLE)
    set(rhp_net_sources
        loopback/loopback.cpp
        detail/http.cpp
        detail/http_connection.cpp
        mdns/metadata.cpp
        websocket/detail/protocol.cpp
        websocket/websocket.cpp
        udp_reliable/detail/packet.cpp
    )
    # The translation units that include Asio (see rhp_net_asio below).
    set(rhp_net_asio_sources
        io_context.cpp
        tcp/tcp.cpp
        mdns/dns.cpp
        mdns/wire.cpp
        mdns/native.cpp
        local/local.cpp
        udp_reliable/udp_reliable.cpp
    )
    # What Asio itself needs at link time (an installed RHP links no Asio target).
    set(rhp_net_private_deps Threads::Threads)
    if(RHP_PLATFORM STREQUAL "WINDOWS")
        list(APPEND rhp_net_private_deps ws2_32 mswsock)
    endif()
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

# Asio is header-only, PRIVATE to the backend translation units and stays in the build tree. They
# compile apart (an OBJECT library folded into rhp_net): Asio's macros (and _WIN32_WINNT) change what
# the standard headers mean, so they can't share the precompiled header the rest of rhp_net uses.
if(RHP_ENABLE)
    add_library(rhp_net_asio OBJECT ${rhp_net_asio_sources})
    target_link_libraries(rhp_net_asio PRIVATE Rhp::core Rhp::platform "$<BUILD_INTERFACE:Rhp::asio>")
    target_compile_features(rhp_net_asio PRIVATE cxx_std_23)
    rhp_apply_platform(rhp_net_asio)
    rhp_set_warnings(rhp_net_asio)
    set_target_properties(rhp_net_asio PROPERTIES FOLDER "rhp")
    rhp_use_shared_pch(rhp_net_asio asio) # a precompiled header of its own, with Asio's macros
    # It defines UNICODE before <windows.h> (Asio includes it): a header included ahead of it would
    # change which Win32 API it gets.
    set_source_files_properties(mdns/native.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS ON)
    # MSVC: the header's object defines what the precompiled header instantiated (Asio's service
    # ids); objects folded in by TARGET_OBJECTS don't bring it, so rhp_net takes it too.
    if(TARGET rhp_pch_asio)
        target_sources(rhp_net PRIVATE $<TARGET_OBJECTS:rhp_pch_asio>)
    endif()
    target_sources(rhp_net PRIVATE $<TARGET_OBJECTS:rhp_net_asio>)
endif()

# Apple's DNS-SD API (dns_sd.h) is part of libSystem: there is no separate library to link.
if(RHP_ENABLE AND RHP_PLATFORM STREQUAL "WINDOWS")
    target_link_libraries(rhp_net PRIVATE dnsapi advapi32 iphlpapi)
endif()

# RHP_UNITY_BUILD: these keep their own translation unit (file-local helpers named like ones in the
# sources batched with them).
set_source_files_properties(local/local.cpp mdns/wire.cpp udp_reliable/udp_reliable.cpp websocket/websocket.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
