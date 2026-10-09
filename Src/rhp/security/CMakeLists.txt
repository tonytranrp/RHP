# Layer 3: authentication and frame integrity. Monocypher is PRIVATE and only the .cpp files include
# monocypher.h. With RHP_ENABLE=OFF only keys and the keyring build (a disabled host still takes a
# keyring); the handshake is not compiled and Monocypher is not fetched.
set(rhp_security_sources key.cpp keyring.cpp)
set(rhp_security_private_deps "")
if(RHP_ENABLE)
    list(APPEND rhp_security_sources psk_keyring.cpp)
    set(rhp_security_private_deps Rhp::monocypher)
endif()

rhp_add_module(security
    HEADERS
        authenticator.hpp
        key.hpp
        keyring.hpp
        psk_keyring.hpp
    SOURCES
        ${rhp_security_sources}
    DEPS
        Rhp::wire
        Rhp::platform
    PRIVATE_DEPS
        ${rhp_security_private_deps}
)
