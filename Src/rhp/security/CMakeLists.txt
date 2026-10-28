# Layer 3: authentication, frame integrity and script signing. Monocypher is PRIVATE and only the
# .cpp files include monocypher.h. With RHP_ENABLE=OFF keys, the keyring, signing keys, trusted
# signers, identity and dev session files still build (a disabled host still takes them); the handshake and
# hashing are not compiled, signing reports kDisabled, and Monocypher is not fetched.
set(rhp_security_sources key.cpp keyring.cpp signing_keys.cpp identity_file.cpp dev_session.cpp http_auth_common.cpp operator_cert.cpp certified.cpp key_store.cpp identity_revocations.cpp pairing.cpp)
set(rhp_security_private_deps "")
if(RHP_ENABLE)
    list(APPEND rhp_security_sources psk_keyring.cpp hash.cpp ed25519.cpp http_auth.cpp key_handle.cpp passphrase.cpp)
    # P-256 runs on the TLS backend's crypto (security/tls/p256.hpp).
    set(rhp_security_private_deps Rhp::monocypher Rhp::tls)
    # Pairing (decision AL10): CPace over X25519.
    list(APPEND rhp_security_sources pairing_cpace.cpp)
else()
    list(APPEND rhp_security_sources ed25519_disabled.cpp http_auth_disabled.cpp key_handle_disabled.cpp)
    list(APPEND rhp_security_sources pairing_cpace_disabled.cpp)
endif()

rhp_add_module(security
    HEADERS
        authenticator.hpp
        certified.hpp
        detail/bytes.hpp
        detail/text.hpp
        dev_session.hpp
        ed25519.hpp
        hash.hpp
        http_auth.hpp
        identity_file.hpp
        identity_revocations.hpp
        key.hpp
        key_handle.hpp
        key_store.hpp
        keyring.hpp
        operator_cert.hpp
        pairing.hpp
        pairing_cpace.hpp
        psk_keyring.hpp
        signer.hpp
    SOURCES
        ${rhp_security_sources}
    DEPS
        Rhp::wire
        Rhp::platform
    PRIVATE_DEPS
        ${rhp_security_private_deps}
)
