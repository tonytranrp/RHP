#pragma once

#include <memory>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/link.hpp>
#include <rhp/security/tls/tls.hpp>

namespace Rhp::session {

// TLS over any link, for the side that connected: the ClientHello goes out when the link starts;
// what the session sends before the handshake ends is held and encrypted once it has.
[[nodiscard]] std::unique_ptr<net::link> tls_client(std::unique_ptr<net::link> inner, std::unique_ptr<security::tls::engine> engine);

// The side that accepted: the peer's first byte decides. 0x16 (a TLS handshake record) starts TLS
// with an engine from `tls` (null: refused, kForbidden); anything else is plaintext, allowed only
// when `plaintext_ok` (otherwise the link closes with kForbidden). What the session sends before
// that is held until it is known.
[[nodiscard]] std::unique_ptr<net::link> tls_server(std::unique_ptr<net::link> inner, std::shared_ptr<security::tls::context> tls, bool plaintext_ok);

// How one endpoint's connections are secured - the rules of net::tls_mode, shared by hosts and
// clients. Dialing: TLS when the endpoint requires it, or when the transport is a network one, the
// address isn't loopback and the endpoint doesn't say insecure_lan. Listening: TLS is accepted from
// anyone who starts it (when a backend exists); plaintext only from loopback peers, over local
// transports, or with insecure_lan - never with require_tls.
//
// insecure_lan over a network transport speaks plaintext only with local peers: loopback, private
// (RFC 1918, RFC 4193) and link-local addresses (net::ip_address::is_local; CGNAT's 100.64/10 and
// a link without an address are not local). A listener refuses plaintext from anyone else, and a dial
// to anyone else is refused (kForbidden): TLS is the only way past that.
class channel_policy {
public:
    // kForbidden when the endpoint needs TLS and the backend can't provide it, or dials a literal
    // address that isn't local with insecure_lan.
    [[nodiscard]] static result<channel_policy> make(const net::endpoint& ep, bool network_transport, const security::tls::backend_ops& backend,
                                                     const security::tls::settings& settings);

    // The endpoint to give the transport (TCP binds or dials non-loopback addresses only when told
    // TLS will be layered on top).
    [[nodiscard]] const net::endpoint& transport_endpoint() const noexcept { return transport_ep_; }
    // A dialed or accepted link, wrapped as the endpoint wants (or as it is). kForbidden for a
    // plaintext link insecure_lan may not use (a dialed peer that isn't local; an accepted one when
    // there is no TLS to offer it instead).
    [[nodiscard]] result<std::unique_ptr<net::link>> wrap(std::unique_ptr<net::link> link) const;
    // A dial's outcome: its link wrapped, or the dial's error as it is.
    [[nodiscard]] result<std::unique_ptr<net::link>> wrap(result<std::unique_ptr<net::link>> dialed) const;
    // Dialing: every connection is TLS. Listening: TLS is available.
    [[nodiscard]] bool tls() const noexcept { return context_ != nullptr; }
    [[nodiscard]] std::string_view backend() const noexcept { return backend_; }

private:
    net::endpoint transport_ep_;
    bool dialing_ = true; // as net::endpoint's default direction: a default policy wraps nothing
    bool dial_tls_ = false;
    bool lan_dial_ = false; // plaintext under insecure_lan: only to a local peer
    // Listening: plaintext is accepted from any peer / from a peer whose link is loopback / from a
    // local peer (insecure_lan).
    bool plaintext_from_anyone_ = false;
    bool plaintext_from_loopback_ = false;
    bool plaintext_from_local_ = false;
    std::shared_ptr<security::tls::context> context_;
    std::string_view backend_;
};

} // namespace Rhp::session
