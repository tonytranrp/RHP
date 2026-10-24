#pragma once

#include <concepts>
#include <cstddef>
#include <memory>
#include <span>
#include <string>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/wire/frame.hpp>

namespace Rhp::security {

// What a successful handshake hands the session: who the peer is and the per-direction MAC keys.
struct auth_grant {
    std::string identity; // the key's name (one lua_State per identity)
    role granted = role::kObserve;
    std::unique_ptr<wire::frame_sealer> outgoing; // seals frames this side sends
    std::unique_ptr<wire::frame_sealer> incoming; // verifies frames this side receives
};

// Host side of one connection's handshake: hello -> challenge, response -> grant.
class host_handshake {
public:
    virtual ~host_handshake() = default;

    // The connection's channel binding (RFC 9266 tls-exporter under TLS, empty otherwise), given
    // before challenge(). Mix it into the proofs: a relay that terminates TLS on both sides then
    // can't pass the handshake. Authenticators that ignore it are open to such relays when the
    // client doesn't check the host's certificate.
    virtual void bind_channel(std::span<const std::byte> binding) { (void)binding; }
    // The challenge for the client's hello (the authenticator's part of it). Unknown keys still get
    // a well-formed challenge, so a client can't probe which key names exist.
    [[nodiscard]] virtual result<value> challenge(const value& hello) = 0;
    // Checks the response; kAuth if it doesn't prove the key.
    [[nodiscard]] virtual result<auth_grant> verify(const value& response) = 0;

protected:
    host_handshake() = default;
    host_handshake(const host_handshake&) = default;
    host_handshake& operator=(const host_handshake&) = default;
};

// Client side: hello, then the response to the host's challenge (which the client verifies first,
// so authentication is mutual), then the keys.
class client_handshake {
public:
    virtual ~client_handshake() = default;

    [[nodiscard]] virtual result<value> hello() = 0;
    // The connection's channel binding, given before respond() (see host_handshake::bind_channel).
    virtual void bind_channel(std::span<const std::byte> binding) { (void)binding; }
    // kAuth if the challenge doesn't prove the host knows the key.
    [[nodiscard]] virtual result<value> respond(const value& challenge) = 0;
    // After respond(): the frame keys (identity and role come from the host's welcome).
    [[nodiscard]] virtual result<auth_grant> finish() = 0;

protected:
    client_handshake() = default;
    client_handshake(const client_handshake&) = default;
    client_handshake& operator=(const client_handshake&) = default;
};

// What a client presents (Rhp::client's identity argument).
template <class C>
concept credential = std::copy_constructible<C> && requires(const C& c) {
    { c.begin() } -> std::same_as<std::unique_ptr<client_handshake>>;
};

// Authenticator policy for Rhp::config<>::auth<...>: starts host handshakes and names the
// credential type its clients use.
template <class A>
concept authenticator = std::copy_constructible<A> && credential<typename A::credential> && requires(const A& a) {
    { a.begin() } -> std::same_as<std::unique_ptr<host_handshake>>;
};

} // namespace Rhp::security
