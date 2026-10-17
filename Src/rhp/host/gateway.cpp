#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <utility>

#include <rhp/host/detail/gateway.hpp>
#include <rhp/net/detail/http_connection.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>

namespace Rhp::host_detail {

namespace {

namespace http = net::detail;
using steady = std::chrono::steady_clock;

constexpr const char* kWhere = "host.http";
constexpr std::size_t kMaxInFlight = 256;        // requests per identity
constexpr std::size_t kReplayPerIdentity = 4096; // accepted proofs per identity per replay window
constexpr std::size_t kMaxRequestToken = 64;
constexpr std::string_view kMsgpack = "application/msgpack";
constexpr std::string_view kModules = "/modules/";
constexpr std::string_view kCancel = "/cancel/";
// With a host clock that isn't steady_clock (config<>::clock), the idle timer can't sleep until a
// deadline in that clock's time: it re-checks this often while an identity is idle.
constexpr std::chrono::milliseconds kCustomClockCheck{25};

// ---- routing -----------------------------------------------------------------------------------

struct operation {
    wire::op code = wire::op::kExec;
    value body;
};

// The media type without parameters ("application/msgpack; charset=binary" → "application/msgpack").
[[nodiscard]] std::string_view media_type(std::string_view content_type) noexcept {
    const auto end = content_type.find(';');
    auto type = content_type.substr(0, end);
    while (!type.empty() && (type.back() == ' ' || type.back() == '\t')) {
        type.remove_suffix(1);
    }
    return type;
}

[[nodiscard]] bool valid_token(std::string_view token) noexcept {
    return !token.empty() && token.size() <= kMaxRequestToken &&
           std::ranges::all_of(token, [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'; });
}

//   POST   /exec                          body: Lua source            → exec
//   GET    /modules                                                   → list
//   GET    /describe                                                  → describe
//   POST   /modules/{name}                body: Lua source            → load / reload
//   GET    /modules/{name}                                            → status
//   DELETE /modules/{name}                                            → unload
//   POST   /modules/{name}/revert                                     → revert
//   POST   /modules/{name}/call/{fn}      body: MessagePack array     → call
// (/cancel is handled by the gateway itself.)
[[nodiscard]] result<operation> route(const http::http_request& r, value signature) {
    const std::string source{reinterpret_cast<const char*>(r.body.view().data()), r.body.size()};
    if (r.target == "/exec" && r.method == "POST") {
        return operation{wire::op::kExec, Rhp::to_value(wire::exec_request{source, "http.exec", std::move(signature)})};
    }
    if (r.target == "/modules" && r.method == "GET") {
        return operation{wire::op::kList, value{}};
    }
    if (r.target == "/describe" && r.method == "GET") {
        return operation{wire::op::kDescribe, value{}};
    }
    if (!r.target.starts_with(kModules)) {
        return fail(errc::kNotFound, "unknown HTTP route", kWhere);
    }
    const auto rest = std::string_view{r.target}.substr(kModules.size());
    const auto slash = rest.find('/');
    const auto name = rest.substr(0, slash);
    const auto suffix = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash);
    if (name.empty()) {
        return fail(errc::kInvalidArgument, "missing module name", kWhere);
    }
    const wire::module_ref module{name};
    if (suffix.empty()) {
        if (r.method == "POST") {
            return operation{wire::op::kLoad, Rhp::to_value(wire::load_request{std::string{name}, source, std::move(signature)})};
        }
        if (r.method == "GET") {
            return operation{wire::op::kStatus, Rhp::to_value(wire::module_request{module})};
        }
        if (r.method == "DELETE") {
            return operation{wire::op::kUnload, Rhp::to_value(wire::unload_request{module, false})};
        }
    }
    if (suffix == "/revert" && r.method == "POST") {
        return operation{wire::op::kRevert, Rhp::to_value(wire::module_request{module})};
    }
    if (constexpr std::string_view kCall = "/call/"; suffix.starts_with(kCall) && r.method == "POST") {
        const auto function = suffix.substr(kCall.size());
        if (function.empty() || function.find('/') != std::string_view::npos) {
            return fail(errc::kInvalidArgument, "call needs one function name", kWhere);
        }
        if (media_type(r.head.header("content-type")) != kMsgpack) {
            return fail(errc::kInvalidArgument, "call arguments must be application/msgpack", kWhere);
        }
        auto args = wire::msgpack::decode(r.body.view());
        if (!args || !args->is_array()) {
            return fail(errc::kTypeMismatch, "call body must be a MessagePack array", kWhere);
        }
        return operation{wire::op::kCall, Rhp::to_value(wire::call_request{module, std::string{function}, std::move(*args->get_if<value::array>())})};
    }
    return fail(errc::kNotFound, "unknown HTTP route", kWhere);
}

// ---- responses ---------------------------------------------------------------------------------

[[nodiscard]] unsigned status_for(errc code) noexcept {
    switch (code) {
    case errc::kOk: return 200;
    case errc::kAuth: return 401;
    case errc::kForbidden:
    case errc::kBadSignature: return 403;
    case errc::kNotFound: return 404;
    case errc::kCancelled: return 409;
    case errc::kLimitExceeded: return 429;
    case errc::kDisabled: return 503;
    case errc::kTimeout: return 504;
    case errc::kProtocol:
    case errc::kInvalidArgument:
    case errc::kTypeMismatch:
    case errc::kOutOfRange: return 400;
    case errc::kTransport:
    case errc::kIntegrity: return 500;
    default: return 422; // the request was understood; the script or module refused it
    }
}

using answer_key = std::optional<security::http_answer_key>;

// `key` signs the answer (X-RHP-Proof) once the request's proof checked out.
void respond(const http::http_reply& reply, unsigned status, const value& body, const answer_key& key = {}) {
    http::http_response response;
    response.status = status;
    if (auto ok = wire::msgpack::encode(body, response.body); !ok) {
        response.status = 500;
        response.body.clear();
        (void)wire::msgpack::encode(Rhp::to_value(ok.error()), response.body);
    }
    if (key) {
        response.headers.emplace_back("X-RHP-Proof", security::http_answer_proof(*key, {response.status, response.content_type, response.body.view()}));
    }
    reply(std::move(response));
}

void respond(const http::http_reply& reply, const error& why, const answer_key& key = {}) {
    respond(reply, status_for(why.code), Rhp::to_value(why), key);
}

} // namespace

// ---- gateway -----------------------------------------------------------------------------------

struct http_gateway::impl {
    impl(net::io_context& context, Rhp::limits budget, gateway_sink& s, bool bind)
        : io(context), limits(budget), sink(s), require_binding(bind), replay(kReplayPerIdentity), idle_timer(context) {}

    struct pending_request {
        http::http_reply reply;
        std::uint64_t connection = 0;
        std::string token; // the client's X-RHP-Request, for POST /cancel/{token}
        answer_key key;    // signs the answer
    };

    struct identity {
        session_id session;
        steady::time_point touched;
        std::uint64_t requests = 0;
        std::map<std::uint64_t, pending_request> pending;
        std::map<std::string, std::uint64_t, std::less<>> tokens;
    };

    struct connection {
        std::unique_ptr<http::http_connection> http;
        bool handshaking = true;                                      // holds one unauthenticated-handshake slot until its proof checks out
        std::optional<std::pair<std::string, std::uint64_t>> request; // (identity, req) in flight
    };

    net::io_context& io;
    Rhp::limits limits;
    gateway_sink& sink;
    bool require_binding = false;
    session::channel_policy policy;
    std::unique_ptr<net::listener> listener;
    std::map<std::uint64_t, connection> connections;
    std::uint64_t next_connection = 0;
    std::map<std::string, identity, std::less<>> identities;
    std::map<session_id, std::string> by_session;
    security::http_replay_guard replay;
    net::io_context::timer idle_timer;

    void accept(std::unique_ptr<net::link> stream) {
        if (!sink.accepting()) {
            return;
        }
        auto secure = policy.wrap(std::move(stream));
        if (!secure || !sink.acquire_handshake()) {
            return;
        }
        utils::scope_guard release{[this] { sink.release_handshake(); }};
        const auto id = ++next_connection;
        const http::http_connection_options options{static_cast<std::size_t>(limits.max_frame), std::chrono::milliseconds{limits.handshake_timeout_ms}};
        auto http = std::make_unique<http::http_connection>(
            io, std::move(*secure), options, [this, id](http::http_request r, http::http_reply reply) { on_request(id, std::move(r), std::move(reply)); },
            [this, id] { on_connection_closed(id); });
        auto& entry = connections[id];
        entry.http = std::move(http);
        release.release(); // the connection entry owns the slot now
        entry.http->start();
    }

    void finish_handshake(connection& c) {
        if (std::exchange(c.handshaking, false)) {
            sink.release_handshake();
        }
    }

    void on_request(std::uint64_t connection_id, http::http_request r, http::http_reply reply) {
        auto& conn = connections.at(connection_id);
        if (!sink.accepting()) {
            respond(reply, make_error(errc::kDisabled, "the host is disabled", kWhere));
            return;
        }
        const security::http_proof proof{r.head.header("authorization"), r.method, r.target, r.head.header("x-rhp-signature"), r.head.header("content-type"), r.body.view(),
                                         r.head.header("x-rhp-channel"), r.binding};
        auto grant = sink.authorize(proof);
        if (grant) {
            if (auto fresh = replay.admit(*grant); !fresh) {
                grant = std::unexpected{std::move(fresh).error()};
            } else if (require_binding && !grant->bound) {
                // Genuine but unbound: answered (and signed), not run.
                respond(reply, make_error(errc::kAuth, "this host accepts only HTTP proofs bound to their TLS connection (X-RHP-Channel: tls-exporter)", kWhere),
                        grant->answer_key);
                return;
            }
        }
        if (!grant) {
            if (grant.error().code == errc::kAuth) {
                sink.refused(r.peer, grant.error());
            }
            respond(reply, grant.error());
            return;
        }
        // Authenticated: the slot goes back now, so a suspended script can't hold it while the
        // same identity sends its cancel.
        finish_handshake(conn);
        const http_peer peer{r.peer, r.encrypted};
        auto& id = open(*grant, peer);
        id.touched = sink.steady_now();
        const answer_key& key = grant->answer_key;
        if (r.method == "POST" && (r.target == "/cancel" || r.target.starts_with(kCancel))) {
            cancel(id, std::string_view{r.target}.substr(std::min(r.target.size(), kCancel.size())), reply, key);
            return;
        }
        auto signature = security::read_http_signature(r.head.header("x-rhp-signature"));
        auto op = signature ? route(r, std::move(*signature)) : result<operation>{std::unexpected{signature.error()}};
        if (!op) {
            respond(reply, op.error(), key);
            return;
        }
        std::string token{r.head.header("x-rhp-request")};
        if (!token.empty() && (!valid_token(token) || id.tokens.contains(token))) {
            respond(reply, make_error(errc::kInvalidArgument, "X-RHP-Request must be a fresh token of up to 64 letters, digits, '.', '_' or '-'", kWhere), key);
            return;
        }
        if (id.pending.size() >= kMaxInFlight) {
            respond(reply, make_error(errc::kLimitExceeded, "too many HTTP requests in flight for this key", kWhere), key);
            return;
        }
        const auto req = ++id.requests;
        if (!sink.submit_http(id.session, req, op->code, std::move(op->body), peer)) {
            respond(reply, make_error(errc::kLimitExceeded, "the host's request queue is full", kWhere), key);
            return;
        }
        if (!token.empty()) {
            id.tokens.emplace(token, req);
        }
        id.pending.emplace(req, pending_request{std::move(reply), connection_id, std::move(token), key});
        conn.request = std::pair{grant->identity, req};
    }

    // The identity's logical session, opened by its first request.
    identity& open(const security::http_grant& grant, const http_peer& peer) {
        auto [it, added] = identities.try_emplace(grant.identity);
        if (added) {
            it->second.session = sink.open_http(grant, peer);
            by_session.emplace(it->second.session, grant.identity);
        }
        return it->second;
    }

    //   POST /cancel           every request this key has in flight
    //   POST /cancel/{token}   the request sent with X-RHP-Request: {token}
    void cancel(identity& id, std::string_view token, const http::http_reply& reply, const answer_key& key) {
        if (token.empty()) {
            sink.cancel_http(id.session, 0, id.requests);
            respond(reply, 200, value{}, key);
            return;
        }
        const auto found = id.tokens.find(token);
        if (found == id.tokens.end()) {
            respond(reply, make_error(errc::kNotFound, "no request in flight with that X-RHP-Request token", kWhere), key);
            return;
        }
        sink.cancel_http(id.session, found->second, 0);
        respond(reply, 200, value{}, key);
    }

    // A client that hung up abandons its request: it is cancelled rather than left to run.
    void on_connection_closed(std::uint64_t connection_id) {
        const auto it = connections.find(connection_id);
        if (it == connections.end()) {
            return;
        }
        finish_handshake(it->second);
        if (it->second.request) {
            const auto& [name, req] = *it->second.request;
            if (auto id = identities.find(name); id != identities.end() && id->second.pending.contains(req)) {
                sink.cancel_http(id->second.session, req, 0);
                forget(id->second, req);
                schedule_expiry();
            }
        }
        connections.erase(it); // destroys the http_connection from its own callback: it holds itself alive
    }

    std::optional<pending_request> forget(identity& id, std::uint64_t req) {
        const auto it = id.pending.find(req);
        if (it == id.pending.end()) {
            return std::nullopt;
        }
        auto request = std::move(it->second);
        id.pending.erase(it);
        if (!request.token.empty()) {
            id.tokens.erase(request.token);
        }
        id.touched = sink.steady_now();
        return request;
    }

    void complete(session_id session, wire::op code, std::uint64_t req, const value& body) {
        const auto name = by_session.find(session);
        if (name == by_session.end()) {
            return;
        }
        auto& id = identities.at(name->second);
        auto request = forget(id, req);
        if (!request) {
            return; // cancelled after its client hung up
        }
        if (const auto conn = connections.find(request->connection); conn != connections.end()) {
            conn->second.request.reset();
        }
        unsigned status = 200;
        if (code == wire::op::kError) {
            const auto err = Rhp::from_value<error>(body);
            status = err ? status_for(err->code) : 500;
        }
        respond(request->reply, status, body, request->key);
        schedule_expiry();
    }

    // ---- idle expiry -------------------------------------------------------------------------

    [[nodiscard]] std::optional<steady::time_point> idle_deadline(const identity& id) const {
        if (limits.gateway_idle_ms == 0 || !id.pending.empty()) {
            return std::nullopt; // a request in flight keeps its identity alive
        }
        return id.touched + std::chrono::milliseconds{limits.gateway_idle_ms};
    }

    // Arms the timer for the earliest idle identity; nothing runs while every identity is busy.
    void schedule_expiry() {
        std::optional<steady::time_point> next;
        for (const auto& [name, id] : identities) {
            if (const auto deadline = idle_deadline(id); deadline && (!next || *deadline < *next)) {
                next = deadline;
            }
        }
        if (!next) {
            idle_timer.cancel();
            return;
        }
        auto delay = std::max(std::chrono::duration_cast<std::chrono::milliseconds>(*next - sink.steady_now()), std::chrono::milliseconds{1});
        if (sink.custom_clock()) {
            delay = std::min(delay, kCustomClockCheck); // that clock may jump: look again soon
        }
        idle_timer.start(delay, [this] { expire(); });
    }

    void expire() {
        const auto now = sink.steady_now();
        for (auto it = identities.begin(); it != identities.end();) {
            if (const auto deadline = idle_deadline(it->second); deadline && *deadline <= now) {
                close_identity(it->first, it->second, make_error(errc::kTimeout, "HTTP identity idle", kWhere));
                it = identities.erase(it);
            } else {
                ++it;
            }
        }
        schedule_expiry();
    }

    void close_identity(std::string_view name, identity& id, const error& why) {
        for (auto& [req, request] : id.pending) {
            respond(request.reply, why, request.key);
        }
        by_session.erase(id.session);
        sink.close_http(id.session, name, why);
    }
};

http_gateway::http_gateway(net::io_context& io, Rhp::limits limits, gateway_sink& sink, bool require_binding)
    : impl_(std::make_unique<impl>(io, limits, sink, require_binding)) {}

http_gateway::~http_gateway() {
    stop();
}

result<void> http_gateway::listen(session::channel_policy policy) {
    impl_->policy = std::move(policy);
    auto listening = net::tcp::listen(impl_->io, impl_->policy.transport_endpoint(), [this](std::unique_ptr<net::link> stream) { impl_->accept(std::move(stream)); });
    if (!listening) {
        return std::unexpected{std::move(listening).error()};
    }
    impl_->listener = std::move(*listening);
    return {};
}

std::uint16_t http_gateway::port() const noexcept {
    return impl_->listener ? impl_->listener->port() : 0;
}

void http_gateway::reply(session_id session, wire::op code, std::uint64_t req, const value& body) {
    if (code == wire::op::kResult || code == wire::op::kError) {
        impl_->complete(session, code, req, body);
    }
}

void http_gateway::stop() {
    impl_->idle_timer.cancel();
    impl_->listener.reset();
    // Pending requests get an answer first; closing links still flush it after they are released.
    const auto stopping = make_error(errc::kTransport, "the host is shutting down", kWhere);
    for (auto& [name, id] : impl_->identities) {
        impl_->close_identity(name, id, stopping);
    }
    impl_->identities.clear();
    for (auto& [id, conn] : impl_->connections) {
        impl_->finish_handshake(conn);
    }
    impl_->connections.clear();
}

} // namespace Rhp::host_detail
