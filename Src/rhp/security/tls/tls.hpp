#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::security::tls {

// What a TLS context is built from. Every field is optional.
//
// Host: `cert_pem` + `key_pem` are its certificate chain and private key; without them the host
// makes an ephemeral self-signed P-256 certificate when it starts.
// Client: without `ca_pem` the host's certificate is not checked - the PSK handshake is bound to
// the TLS channel (RFC 9266 tls-exporter), so a relay that terminates TLS on both sides fails
// authentication. With `ca_pem` the chain must verify against it, and against `server_name` if set: a
// DNS name, or an IP address in text ("192.0.2.7", "2001:db8::7"), checked against the certificate's
// IP addresses.
struct settings {
    std::string cert_pem;
    std::string key_pem;
    std::string ca_pem;
    std::string server_name;
};

inline constexpr std::size_t kBindingSize = 32;
using channel_binding = std::array<std::byte, kBindingSize>;

// One TLS 1.3 connection without I/O of its own: ciphertext goes in and out through buffers, so it
// runs over any Rhp::net::link. Not thread-safe; one link drives it.
class engine {
public:
    virtual ~engine() = default;

    // A client's first flight (ClientHello) into `to_peer`; nothing for a server.
    [[nodiscard]] virtual result<void> start(utils::byte_buffer& to_peer) = 0;
    // Ciphertext from the peer: application bytes are appended to `plain`, handshake messages and
    // alerts for the peer to `to_peer`. A peer's close_notify is reported as kTransport.
    [[nodiscard]] virtual result<void> receive(utils::bytes_view from_peer, utils::byte_buffer& plain, utils::byte_buffer& to_peer) = 0;
    // Application bytes, once established().
    [[nodiscard]] virtual result<void> send(utils::bytes_view plain, utils::byte_buffer& to_peer) = 0;
    // close_notify (best effort).
    virtual void close(utils::byte_buffer& to_peer) noexcept = 0;
    [[nodiscard]] virtual bool established() const noexcept = 0;
    // RFC 9266 tls-exporter: 32 bytes exported with label "EXPORTER-Channel-Binding" and an empty
    // context. Both ends of one TLS connection get the same bytes; two different connections never do.
    [[nodiscard]] virtual result<channel_binding> binding() = 0;

protected:
    engine() = default;
    engine(const engine&) = default;
    engine& operator=(const engine&) = default;
};

// Shared configuration (certificates, trust) that makes one engine per connection. Thread-safe.
class context {
public:
    virtual ~context() = default;

    [[nodiscard]] virtual result<std::unique_ptr<engine>> make_engine() = 0;

protected:
    context() = default;
    context(const context&) = default;
    context& operator=(const context&) = default;
};

// TLS backend policy for Rhp::config<>::tls<...>: a name and two context factories.
template <class B>
concept backend = requires(const settings& s) {
    { B::name } -> std::convertible_to<std::string_view>;
    { B::server(s) } -> std::same_as<result<std::shared_ptr<context>>>;
    { B::client(s) } -> std::same_as<result<std::shared_ptr<context>>>;
};

// A backend as function pointers, so hosts and clients stay out of templates.
struct backend_ops {
    std::string_view name;
    result<std::shared_ptr<context>> (*server)(const settings& s) = nullptr;
    result<std::shared_ptr<context>> (*client)(const settings& s) = nullptr;

    [[nodiscard]] bool available() const noexcept { return server != nullptr && client != nullptr; }
};

// No TLS: every endpoint that would need it fails with kForbidden (use Rhp::net::insecure_lan).
struct none {
    static constexpr std::string_view name = "none";

    static result<std::shared_ptr<context>> server(const settings&) { return fail(errc::kDisabled, "built without TLS", "tls"); }
    static result<std::shared_ptr<context>> client(const settings&) { return fail(errc::kDisabled, "built without TLS", "tls"); }
};

template <backend B>
inline constexpr backend_ops backend_ops_for{B::name, &B::server, &B::client};

template <>
inline constexpr backend_ops backend_ops_for<none>{none::name, nullptr, nullptr};

static_assert(backend<none>);

} // namespace Rhp::security::tls
