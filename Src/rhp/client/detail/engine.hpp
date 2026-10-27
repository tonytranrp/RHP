#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

#include <rhp/client/detail/requests.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

struct client_options {
    // How long connect() (or the first call) waits for the handshake - in reverse mode, for a host
    // to dial in and finish it.
    std::chrono::milliseconds connect_timeout{10'000};
    // How long a call waits for its reply; 0 = until the reply or the session ends (the
    // heartbeat ends a session whose host stopped answering).
    std::chrono::milliseconds request_timeout{0};
    // Every print() line the host sends this client (its own requests' and the identity's
    // broadcasts), with the request it belongs to (0 = none). On the network thread (the calling
    // thread with io<zero_threads>): keep it short and never call the client from it.
    std::function<void(std::uint64_t request, std::string_view line)> on_output{};
    // Every rhp.emit(value), with its request and module. Same thread rules as on_output.
    std::function<void(std::uint64_t request, module_id module, const value& v)> on_emit{};
    // Bytes per blob chunk (each one request, at most limits.max_frame minus framing) and how
    // many chunks may be in flight at once.
    std::size_t blob_chunk = 1u << 20;
    std::size_t blob_window = 4;
    // How long a received frame's ack waits for an outgoing frame to carry it (session::options);
    // 0 acks every read at once.
    std::uint32_t ack_delay_ms = 5;
    // TLS: how the host's certificate is checked (ca_pem, server_name; empty = not checked, the
    // handshake is bound to the TLS channel instead) and, in reverse mode where the client listens,
    // its own certificate (cert_pem + key_pem; empty = ephemeral self-signed).
    security::tls::settings tls{};
};

// One delivery of a subscribed event (client.on). Views are valid during the callback only.
struct remote_event {
    std::string_view name{};
    module_id module{}; // the publishing module on the host (0: a C++ event or the sandbox itself)
    std::span<const value> args{};
    std::uint64_t dropped = 0; // deliveries to this session the host dropped since the previous one
};

using remote_event_fn = std::function<void(const remote_event&)>;

} // namespace Rhp

namespace Rhp::net {
class io_context;
} // namespace Rhp::net

namespace Rhp::client_detail {

struct setup {
    net::endpoint ep;
    net::transport_ops transport;
    security::tls::backend_ops tls;
    wire::codec_ops codec;
    std::function<std::unique_ptr<security::client_handshake>()> begin_handshake;
    Rhp::limits limits{};
    bool io_thread = true; // false: the calling thread runs the network while it waits
    client_options options;
    // Signs the scripts this client sends (the client's signing key); empty sends them unsigned.
    sign_fn sign;
    // A reactor shared with other engines (a fleet's) instead of one of the engine's own. Its owner
    // runs it (one thread, or the waits when io_thread is false), outlives the engine, never calls
    // run_io for it, and destroys the engine on the thread running the reactor or once it stopped.
    net::io_context* shared_io = nullptr;
};

// What an RHP_ENABLE=0 client or fleet reports from every call (`where`: the call).
[[nodiscard]] inline std::unexpected<error> compiled_out(std::string_view where) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{where});
}

class engine;

struct engine_deleter {
    void operator()(engine* e) const noexcept;
};

using engine_ptr = std::unique_ptr<engine, engine_deleter>;

// Gets the kResult body of a request, or the error it ended with.
using completion = std::function<void(result<value>)>;

[[nodiscard]] engine_ptr make_engine(setup s);
// Dials (once) - or, in reverse mode, listens and waits for a host to dial in - and waits for the
// handshake.
[[nodiscard]] result<void> connect(engine& e);
// Reverse mode: starts listening (once) and returns the bound port. kInvalidArgument when dialing.
[[nodiscard]] result<std::uint16_t> port(engine& e);
// Sends one request and waits for its kResult body (or the kError it gets).
[[nodiscard]] result<value> request(engine& e, wire::op code, value body);
// The signature setup::sign gives a script's source (nil without a signer). Any thread.
[[nodiscard]] result<value> sign(const engine& e, std::string_view source);
// Sends one request without waiting; `done` runs once with the outcome, on the network thread
// (or right away on this thread if the client is already closed). Connects first if needed.
// Returns the request id (for cancel_request).
std::uint64_t submit(engine& e, wire::op code, value body, completion done);
// Sends a blob to a host sink in chunks (a window of them in flight) and waits for the verdict.
[[nodiscard]] result<void> blob(engine& e, std::string_view sink, std::string_view name, std::span<const std::byte> data);
// Asks the host to stop every request of this client in flight (0) or one. Any thread; doesn't wait.
void cancel(engine& e, std::uint64_t req = 0) noexcept;
// Closes the session (the host reverts this identity if it was its last session) and waits briefly
// for the close to go out.
void close(engine& e) noexcept;
// Adds a callback for `name` (subscribing on the host the first time); returns its id.
[[nodiscard]] result<std::uint64_t> subscribe(engine& e, std::string_view name, remote_event_fn fn);
// Removes one callback (unsubscribing on the host with the last one for its name).
[[nodiscard]] result<void> unsubscribe(engine& e, std::uint64_t id);
// zero_threads: runs whatever the network has ready, without blocking. No-op with an I/O thread.
void poll(engine& e);
// zero_threads: what an async result's get() runs while it waits; empty with an I/O thread.
[[nodiscard]] std::function<void(std::chrono::milliseconds)> pump_fn(engine& e);
// True on this engine's own network thread, where waiting for one of its results would wait for
// itself. Compares the engine's address only: safe to call after the engine is gone.
[[nodiscard]] std::function<bool()> blocking_check(engine& e);
void run_io(engine& e, std::stop_token stop);

struct session_info {
    bool connected = false;
    bool closed = false; // terminal: a fresh client is required, as distinct from a resumable detach
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::string host_platform;
    bool tls = false;          // the current connection is TLS
    std::uint64_t resumes = 0; // times the session continued on a new connection
};
[[nodiscard]] session_info info(const engine& e);

} // namespace Rhp::client_detail
