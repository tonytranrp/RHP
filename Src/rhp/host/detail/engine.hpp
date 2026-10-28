#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/hub.hpp>
#include <rhp/net/discovery.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/http_auth.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

struct host_options {
    // Responses kept per session for idempotent retries (by the client's idempotency key): at most
    // this many, and at most this many bytes (older ones are dropped first).
    std::size_t idempotency_cache = 256;
    std::size_t idempotency_bytes = 16u << 20;
    // Messages the network thread may queue for pump() before it holds them back itself.
    std::size_t inbox_capacity = 4096;
    // TLS: the host's certificate (cert_pem + key_pem; empty = an ephemeral self-signed one) and,
    // in reverse mode where the host dials, how it checks the client's (ca_pem, server_name).
    security::tls::settings tls{};
    // Optional HTTP/1.1 listener (Docs/guide/networking.md): the same identities, roles, signing,
    // dispatcher and TLS settings as native sessions. Needs a security::http_authenticator.
    std::optional<net::endpoint> gateway{};
    // Refuse HTTP requests whose proof isn't bound to their TLS connection (X-RHP-Channel:
    // tls-exporter), so a relay that terminates TLS can't pass any request; plaintext
    // connections can't bind, so they are refused too.
    bool http_require_binding = false;
    // What a failing timer, frame callback, event handler or task does in every identity's sandbox
    // when the script sets no on_error (Rhp::script::handler_error_policy).
    script::handler_error_policy handler_errors = script::handler_error_policy::kReport;
    // Subscribed events (client.on) sent to one session per pump(); the rest are dropped and the
    // next delivery says how many. This bounds the rate, not the backlog of a detached session.
    std::size_t remote_events_per_pump = 256;
    // How long a received frame's ack waits for an outgoing frame to carry it (session::options);
    // 0 acks every read at once.
    std::uint32_t ack_delay_ms = 5;
    // Raises the host's hardening above its config's (Rhp::hardening; never lowers it): the host
    // runs at the strictest of RHP_HARDENING, config<>::hardening and this. A host whose signer is
    // unsigned_scripts doesn't start above kDev (kForbidden from port()).
    Rhp::hardening hardening = Rhp::hardening::kDev;
    // Observe identities' limits (empty: the config's). From hardening kLan up they are capped by
    // Rhp::kObserveCaps; in kProduction every identity's are capped by Rhp::kProductionCaps too.
    std::optional<Rhp::limits> observe_limits{};
    // A dev session (decision AL7) for this app name; empty = none. In a dev build at hardening
    // kDev, a host listening on a loopback address or local IPC (and an HTTP gateway, if any, on a
    // loopback address: it accepts the same identities) adds an admin identity of its own
    // (a fresh PSK and Ed25519 signer) and writes how to reach it to
    // security::dev_session_path(app), owner-only, for `rhp-cli connect --dev app`; the file goes
    // when the host does. Needs config<>::auth<psk_keyring> and signer<ed25519> (the defaults).
    // Anywhere else the host doesn't start (kForbidden from port()); nor, gateway included, when the
    // file can't be written.
    std::string dev_session{};
};

// A whole blob as a sink sees it (host.on_blob). Views are valid during the sink call only.
struct blob_view {
    std::string_view sink;
    std::string_view name;     // what the client called it (a file name, free-form)
    std::string_view identity; // who sent it
    std::span<const std::byte> bytes;
};

// A blob sink: takes the bytes or says why not (the error goes back to the client).
using blob_fn = std::function<result<void>(const blob_view&)>;

} // namespace Rhp

namespace Rhp::host_detail {

// Everything the engine needs from a config, type-erased so the engine compiles once (host.cpp and engine_*.cpp).
struct setup {
    net::endpoint ep;
    net::transport_ops transport;
    security::tls::backend_ops tls;
    wire::codec_ops codec;
    std::function<std::unique_ptr<security::host_handshake>()> begin_handshake;
    // The signer policy's check of a script: who signed it, or kBadSignature.
    std::function<result<std::string>(std::string_view source, const value& signature)> verify;
    std::shared_ptr<event::hub> events;
    std::shared_ptr<event::script_hub> script_events;
    Rhp::limits limits{};
    bool io_thread = true; // false: pump() polls the network
    std::function<bool(log_level)> log_enabled;
    std::function<void(log_level, std::string_view)> log;
    script::clock_fn clock;
    bool custom_clock = false; // `clock` isn't std::chrono::steady_clock (a test or game clock)
    host_options options;
    // The authenticator's HTTP proof check; empty when it isn't a security::http_authenticator.
    std::function<result<security::http_grant>(const security::http_proof&, std::chrono::system_clock::time_point)> http_auth;
    net::discovery_ops discovery;
    // The strictest of the config's hardening and host_options::hardening (the engine adds the build's).
    Rhp::hardening hardening = kBuildHardening;
    bool unsigned_scripts = false; // the config's signer is security::unsigned_scripts
    // host_options::dev_session's identity, already in the authenticator (admin) and the trusted
    // signers, or why the config can't have one. Set by host<Cfg> in a dev build only.
    result<security::identity_file> dev_identity{};
};

using installer = result<void> (*)(script::sandbox& box);

// A release manager as the engine serves it (host.serve): answers the release requests and is
// pumped with the host. Built by host_detail::bridge (host/releases.cpp).
struct release_bridge {
    std::function<result<value>(wire::op code, const value& body)> handle;
    std::function<void()> pump;
    // Raises the manager's hardening to the host's when the engine starts serving it.
    std::function<result<void>(Rhp::hardening)> harden;
    // Subscribes to the manager's events when the engine starts serving (publishes release_changed);
    // the engine drops the subscription before it goes.
    std::function<Rhp::subscription(std::function<void(event::release_changed)>)> on_event;
};

template <script::installable L>
result<void> install_into(script::sandbox& box) {
    return box.install<L>();
}

class engine;

struct engine_deleter {
    void operator()(engine* e) const noexcept;
};

using engine_ptr = std::unique_ptr<engine, engine_deleter>;

// What an RHP_ENABLE=0 host reports from every result-bearing call (`where`: the call).
[[nodiscard]] inline std::unexpected<error> compiled_out(std::string_view where) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{where});
}

// The name of a dev session's identity and signer (host_options::dev_session): host<Cfg> generates
// both for the run and adds them to its authenticator and trusted signers.
inline constexpr std::string_view kDevSessionIdentity = "dev-session";

// Starts listening (or, in reverse mode, dialing); errors are kept and reported by port().
[[nodiscard]] engine_ptr make_engine(setup s);
// The port the host listens on (0 in reverse mode), or why it isn't listening.
[[nodiscard]] result<std::uint16_t> port(const engine& e);
[[nodiscard]] result<std::uint16_t> gateway_port(const engine& e);
result<void> advertise(engine& e, net::advertise_options options);
result<void> discovery_status(engine& e);
result<void> install(engine& e, std::string_view name, installer fn);
// Pump thread (any one thread before the first pump()). kAlreadyLoaded if one is served already.
result<void> serve_releases(engine& e, release_bridge bridge);
result<void> add_blob_sink(engine& e, std::string_view name, blob_fn fn, role need);
void set_enabled(engine& e, bool on) noexcept;
[[nodiscard]] bool enabled(const engine& e) noexcept;
void pump(engine& e);
// Closes every session with a reason and waits briefly for that to go out (before the network stops).
void goodbye(engine& e);
// The network loop (the io_runner's body); returns once `stop` is signalled.
void run_io(engine& e, std::stop_token stop);
[[nodiscard]] std::size_t sessions(const engine& e) noexcept;
[[nodiscard]] std::size_t identities(const engine& e) noexcept;

} // namespace Rhp::host_detail
