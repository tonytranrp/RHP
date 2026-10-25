#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/client/detail/engine.hpp>
#include <rhp/client/pending.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

using wire::module_ref;
using wire::module_status;
using wire::revert_summary;

// Talks to an Rhp::host: authenticates with a credential (a key name + secret for psk_keyring),
// signs every script it sends with its signing key (Ed25519 by default), then sends requests and
// blocks for their results - or, through async(), returns Rhp::pending results to await, chain or
// turn into std::futures. Script output arrives through client_options::on_output / on_emit.
//
//   auto id = *Rhp::security::identity_file::load("dev.rhpid");
//   Rhp::client<> c{Rhp::endpoint::dial("127.0.0.1", 7777), id.credential(), *id.signer_key()};
//   auto g = c.exec<double>("return game.gravity");          // Rhp::result<double>
//   auto mod = c.load("low_grav", source);                   // signed automatically
//   c.call(*mod, "set", 1.6);
//   auto tick = co_await c.async().exec<int>("return game.tick");
//   c.unload(*mod);
//
// Without a signing key the host runs this client's code only if its session is observe (or the
// host's config uses Rhp::security::unsigned_scripts).
//
// Reverse mode: with Rhp::endpoint::listen(...) the client listens and the host dials in (phones,
// NAT). port() starts listening and reports the port; connect() waits for a host. When that host's
// session ends, calls in flight fail, and the next call waits for a host to dial in again.
//
// Calls may come from any thread (with the default io<owned_io_thread>); cancel() may be called
// while another thread waits. With io<zero_threads> the calling thread runs the network itself,
// so use the client from one thread - and call poll() at least once per heartbeat (2 s by default)
// while idle, or the host drops the session (and reverts what it did) after heartbeat_misses.
// Destroying the client ends its session: if it was its identity's last one, the host reverts
// everything that identity did (except modules an admin pinned).
//
// With RHP_ENABLE=0 every call reports kDisabled.
template <configuration Cfg = config<>>
class client {
public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;
    template <class T>
    using pending_t = pending<T, typename Cfg::errors_t>;
    using signing_key_t = typename Cfg::signing_key_t;

    client(net::endpoint ep, typename Cfg::credential_t identity, client_options options = {}) : client(std::move(ep), std::move(identity), std::nullopt, std::move(options)) {}

    client(net::endpoint ep, typename Cfg::credential_t identity, signing_key_t key, client_options options = {})
        : client(std::move(ep), std::move(identity), std::optional<signing_key_t>{std::move(key)}, std::move(options)) {}

    ~client() {
#if RHP_ENABLE
        client_detail::close(*engine_);
        runner_.stop();
        engine_.reset();
#endif
    }

    client(const client&) = delete;
    client& operator=(const client&) = delete;
    client(client&&) = delete;
    client& operator=(client&&) = delete;

    // Connects and authenticates now (otherwise the first call does). kAuth, kTransport, kTimeout,
    // kForbidden (a non-loopback address without insecure_lan), kProtocolRevisionMismatch. In
    // reverse mode: waits (connect_timeout) for a host to dial in.
    return_t<void> connect() { return finish(do_connect()); }

    // Reverse mode: starts listening (if it hasn't yet) and returns the port (the real one after
    // listening on port 0). kInvalidArgument for a client that dials.
    [[nodiscard]] return_t<std::uint16_t> port() {
#if RHP_ENABLE
        return finish(client_detail::port(*engine_));
#else
        return finish(result<std::uint16_t>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client")});
#endif
    }

    // ---- scripts --------------------------------------------------------------------------------

    // Runs source in this identity's scratch module (effects kept until reverted or disconnect).
    return_t<value_list> exec(std::string_view source, std::string_view chunk = "exec") { return finish(values(code_request(wire::op::kExec, exec_body(source, chunk)))); }

    // The first returned value, converted (nil if none).
    template <from_value_convertible T>
    return_t<T> exec(std::string_view source, std::string_view chunk = "exec") {
        return finish(first<T>(code_request(wire::op::kExec, exec_body(source, chunk))));
    }

    return_t<module_id> load(std::string_view name, std::string_view source) { return finish(as<module_id>(code_request(wire::op::kLoad, load_body(name, source)))); }

    return_t<value_list> call(module_ref mod, std::string_view function, std::span<const value> args = {}) {
        return finish(values(send(wire::op::kCall, wire::call_request{std::move(mod), std::string{function}, value::array(args.begin(), args.end())})));
    }

    template <to_value_convertible A0, to_value_convertible... A>
    return_t<value_list> call(module_ref mod, std::string_view function, const A0& a0, const A&... rest) {
        const value args[] = {Rhp::to_value(a0), Rhp::to_value(rest)...};
        return call(std::move(mod), function, std::span<const value>{args});
    }

    // ---- lifecycle --------------------------------------------------------------------------------

    // Transactional reload; the new revision (0 = deferred).
    return_t<revision_id> reload(module_ref mod, std::string_view source) {
        return finish(as<revision_id>(code_request(wire::op::kReload, reload_body(std::move(mod), source))));
    }

    return_t<revision_id> rollback(module_ref mod, std::size_t steps = 1) {
        return finish(as<revision_id>(send(wire::op::kRollback, wire::rollback_request{std::move(mod), steps})));
    }

    return_t<revert_summary> revert(module_ref mod) { return finish(as<revert_summary>(send(wire::op::kRevert, wire::module_request{std::move(mod)}))); }

    // `force` unloads even while other modules require this one (they then get kUnloaded).
    return_t<revert_summary> unload(module_ref mod, bool force = false) {
        return finish(as<revert_summary>(send(wire::op::kUnload, wire::unload_request{std::move(mod), force})));
    }

    return_t<void> checkpoint(std::string_view tag) { return finish(nothing(send(wire::op::kCheckpoint, wire::tag_request{std::string{tag}}))); }

    return_t<revert_summary> revert_to(std::string_view tag) {
        return finish(as<revert_summary>(send(wire::op::kRevertTo, wire::tag_request{std::string{tag}})));
    }

    // Admin: unloads every module of every identity on the host (pinned ones too).
    return_t<revert_summary> revert_all() { return finish(as<revert_summary>(raw(wire::op::kRevertAll, value{}))); }

    // Admin: the host keeps the module (and what it requires) when this identity's last session
    // ends; revert / unload refuse it (kForbidden) until unpin.
    return_t<void> pin(module_ref mod) { return finish(nothing(send(wire::op::kPin, wire::module_request{std::move(mod)}))); }
    return_t<void> unpin(module_ref mod) { return finish(nothing(send(wire::op::kUnpin, wire::module_request{std::move(mod)}))); }

    // Pushes bytes to a host blob sink (host.on_blob), in chunks, and returns the sink's verdict.
    // `name` is passed to the sink (a file name, free-form).
    return_t<void> blob(std::string_view sink, std::span<const std::byte> bytes, std::string_view name = {}) {
#if RHP_ENABLE
        return finish(client_detail::blob(*engine_, sink, name, bytes));
#else
        (void)sink;
        (void)bytes;
        (void)name;
        return finish(result<void>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client")});
#endif
    }

    // Calls `fn` for every delivery of `name` by the host: a C++ lua_event of that name, or an
    // rhp.publish of this identity's scripts ("*": every publish, and every delivery this client
    // gets). The first callback for a name subscribes on the host (a blocking call). `fn` runs on the
    // network thread (inside the waits with io<zero_threads>): keep it short and never call the
    // client from it. Returns the callback's id for off().
    return_t<std::uint64_t> on(std::string_view name, remote_event_fn fn) {
#if RHP_ENABLE
        return finish(client_detail::subscribe(*engine_, name, std::move(fn)));
#else
        (void)name;
        (void)fn;
        return finish(result<std::uint64_t>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client")});
#endif
    }

    // Removes one callback; the host stops sending its event once the name's last callback is gone.
    return_t<void> off(std::uint64_t callback) {
#if RHP_ENABLE
        return finish(client_detail::unsubscribe(*engine_, callback));
#else
        (void)callback;
        return finish(result<void>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client")});
#endif
    }

    // Stops every request this client has in flight (any thread; doesn't wait). The calls waiting
    // for them get kCancelled.
    void cancel() noexcept {
#if RHP_ENABLE
        client_detail::cancel(*engine_, 0);
#endif
    }

    // Stops one request (an async call's pending::request()). 0 names no request (a call that
    // never started, e.g. on a closed client) and does nothing: it never means "all".
    void cancel(std::uint64_t request) noexcept {
#if RHP_ENABLE
        if (request != 0) {
            client_detail::cancel(*engine_, request);
        }
#else
        (void)request;
#endif
    }

    // ---- introspection ------------------------------------------------------------------------------

    return_t<std::vector<module_status>> list() { return finish(as<std::vector<module_status>>(raw(wire::op::kList, value{}))); }

    return_t<module_status> status(module_ref mod) { return finish(as<module_status>(send(wire::op::kStatus, wire::module_request{std::move(mod)}))); }

    // LuaLS annotations for everything this identity can use on the host.
    return_t<std::string> describe() { return finish(as<std::string>(raw(wire::op::kDescribe, value{}))); }

    // ---- asynchronous calls ----------------------------------------------------------------------------

    // The same operations without blocking: each returns an Rhp::pending (then / get / future /
    // co_await). Results arrive on the network thread.
    class async_calls {
    public:
        explicit async_calls(client& c) noexcept : c_(&c) {}

        pending_t<value_list> exec(std::string_view source, std::string_view chunk = "exec") {
            return c_->template start<value_list>(wire::op::kExec, c_->exec_body(source, chunk), &client::values);
        }

        template <from_value_convertible T>
        pending_t<T> exec(std::string_view source, std::string_view chunk = "exec") {
            return c_->template start<T>(wire::op::kExec, c_->exec_body(source, chunk), &client::template first<T>);
        }

        pending_t<module_id> load(std::string_view name, std::string_view source) {
            return c_->template start<module_id>(wire::op::kLoad, c_->load_body(name, source), &client::template as<module_id>);
        }

        pending_t<value_list> call(module_ref mod, std::string_view function, std::span<const value> args = {}) {
            return c_->template start<value_list>(
                wire::op::kCall, Rhp::to_value(wire::call_request{std::move(mod), std::string{function}, value::array(args.begin(), args.end())}), &client::values);
        }

        template <to_value_convertible A0, to_value_convertible... A>
        pending_t<value_list> call(module_ref mod, std::string_view function, const A0& a0, const A&... rest) {
            const value args[] = {Rhp::to_value(a0), Rhp::to_value(rest)...};
            return call(std::move(mod), function, std::span<const value>{args});
        }

        pending_t<revision_id> reload(module_ref mod, std::string_view source) {
            return c_->template start<revision_id>(wire::op::kReload, c_->reload_body(std::move(mod), source), &client::template as<revision_id>);
        }

        pending_t<revision_id> rollback(module_ref mod, std::size_t steps = 1) {
            return c_->template start<revision_id>(wire::op::kRollback, Rhp::to_value(wire::rollback_request{std::move(mod), steps}), &client::template as<revision_id>);
        }

        pending_t<revert_summary> revert(module_ref mod) {
            return c_->template start<revert_summary>(wire::op::kRevert, Rhp::to_value(wire::module_request{std::move(mod)}), &client::template as<revert_summary>);
        }

        pending_t<revert_summary> unload(module_ref mod, bool force = false) {
            return c_->template start<revert_summary>(wire::op::kUnload, Rhp::to_value(wire::unload_request{std::move(mod), force}), &client::template as<revert_summary>);
        }

        pending_t<std::vector<module_status>> list() {
            return c_->template start<std::vector<module_status>>(wire::op::kList, value{}, &client::template as<std::vector<module_status>>);
        }

        pending_t<module_status> status(module_ref mod) {
            return c_->template start<module_status>(wire::op::kStatus, Rhp::to_value(wire::module_request{std::move(mod)}), &client::template as<module_status>);
        }

        pending_t<std::string> describe() { return c_->template start<std::string>(wire::op::kDescribe, value{}, &client::template as<std::string>); }

    private:
        client* c_;
    };

    [[nodiscard]] async_calls async() noexcept { return async_calls{*this}; }

    // Shortcuts: exec with a callback (on the network thread), or as a std::future.
    template <class T = value_list, std::invocable<result<T>> F>
        requires std::same_as<T, value_list> || from_value_convertible<T>
    std::uint64_t exec_async(std::string_view source, F on_done) {
        auto p = [&] {
            if constexpr (std::is_same_v<T, value_list>) {
                return async().exec(source);
            } else {
                return async().template exec<T>(source);
            }
        }();
        const std::uint64_t id = p.request();
        std::move(p).then(std::move(on_done));
        return id;
    }

    template <from_value_convertible T>
    [[nodiscard]] std::future<typename pending_t<T>::future_type> exec_future(std::string_view source) {
        return async().template exec<T>(source).future();
    }

    // io<zero_threads>: handles whatever the network has ready (pings, streamed output, async
    // results) without blocking. Call it from your loop between requests. No-op with an I/O thread.
    // A callback run here may destroy this client: the engine stays alive until poll() returns.
    void poll() {
#if RHP_ENABLE
        const auto keep = engine_;
        client_detail::poll(*keep);
#endif
    }

    [[nodiscard]] bool connected() const { return info().connected; }
    // Who the host says we are, once connected.
    [[nodiscard]] client_detail::session_info info() const {
#if RHP_ENABLE
        return client_detail::info(*engine_);
#else
        return {};
#endif
    }

private:
    client(net::endpoint ep, typename Cfg::credential_t identity, std::optional<signing_key_t> key, client_options options) : signer_(std::move(key)) {
#if RHP_ENABLE
        client_detail::setup s;
        s.ep = std::move(ep);
        s.transport = net::transport_ops_for<typename Cfg::transport_t>;
        s.tls = security::tls::backend_ops_for<typename Cfg::tls_t>;
        s.codec = wire::codec_ops_for<typename Cfg::codec_t>;
        s.begin_handshake = [identity = std::move(identity)] { return identity.begin(); };
        s.limits = Cfg::limits_v;
        s.io_thread = Cfg::io_t::kOwnsThread;
        s.options = std::move(options);
        engine_ = client_detail::make_engine(std::move(s));
        if constexpr (Cfg::io_t::kOwnsThread) {
            // The I/O thread shares the engine: a client destroyed from one of its own callbacks
            // leaves the engine to that thread, which destroys it once the network has stopped.
            runner_.start([engine = engine_](std::stop_token stop) { client_detail::run_io(*engine, std::move(stop)); });
        }
#else
        (void)ep;
        (void)identity;
        (void)options;
#endif
    }

    template <class T>
    static return_t<T> finish(result<T>&& r) {
        return Cfg::errors_t::finish(std::move(r));
    }

    // The signature this client attaches to `source` (nil without a key).
    [[nodiscard]] result<value> sign(std::string_view source) const {
        if (!signer_) {
            return value{};
        }
        return signer_->sign(source);
    }

    // A code-carrying request body (exec / load / reload) with its signature, or why it couldn't be signed.
    [[nodiscard]] result<value> exec_body(std::string_view source, std::string_view chunk) const {
        auto signature = sign(source);
        if (!signature) {
            return std::unexpected{std::move(signature).error()};
        }
        return Rhp::to_value(wire::exec_request{std::string{source}, std::string{chunk}, std::move(*signature)});
    }

    [[nodiscard]] result<value> load_body(std::string_view name, std::string_view source) const {
        auto signature = sign(source);
        if (!signature) {
            return std::unexpected{std::move(signature).error()};
        }
        return Rhp::to_value(wire::load_request{std::string{name}, std::string{source}, std::move(*signature)});
    }

    [[nodiscard]] result<value> reload_body(module_ref mod, std::string_view source) const {
        auto signature = sign(source);
        if (!signature) {
            return std::unexpected{std::move(signature).error()};
        }
        return Rhp::to_value(wire::reload_request{std::move(mod), std::string{source}, std::move(*signature)});
    }

    result<value> code_request(wire::op code, result<value> body) {
        if (!body) {
            return std::unexpected{std::move(body).error()};
        }
        return raw(code, std::move(*body));
    }

    result<void> do_connect() {
#if RHP_ENABLE
        return client_detail::connect(*engine_);
#else
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client");
#endif
    }

    result<value> raw(wire::op code, value body) {
#if RHP_ENABLE
        return client_detail::request(*engine_, code, std::move(body));
#else
        (void)code;
        (void)body;
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client");
#endif
    }

    template <class Message>
    result<value> send(wire::op code, const Message& m) {
        return raw(code, Rhp::to_value(m));
    }

    // Starts an async call whose reply body becomes a T through `convert`.
    template <class T>
    pending_t<T> start(wire::op code, result<value> body, result<T> (*convert)(result<value>&&)) {
#if RHP_ENABLE
        auto state = std::make_shared<client_detail::pending_state<T>>(0, client_detail::pump_fn(*engine_), client_detail::blocking_check(*engine_));
        if (!body) {
            state->complete(std::unexpected{std::move(body).error()});
            return pending_t<T>{std::move(state)};
        }
        const std::uint64_t id = client_detail::submit(*engine_, code, std::move(*body), [state, convert](result<value> r) { state->complete(convert(std::move(r))); });
        state->set_request(id);
        return pending_t<T>{std::move(state)};
#else
        (void)code;
        (void)body;
        (void)convert;
        auto state = std::make_shared<client_detail::pending_state<T>>(0, nullptr);
        state->complete(fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "client"));
        return pending_t<T>{std::move(state)};
#endif
    }

    template <class T>
    static result<T> as(result<value>&& r) {
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return Rhp::from_value<T>(*r);
    }

    static result<value_list> values(result<value>&& r) {
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        if (auto* items = r->get_if<value::array>()) {
            return std::move(*items);
        }
        return value_list{std::move(*r)};
    }

    template <class T>
    static result<T> first(result<value>&& r) {
        auto list = values(std::move(r));
        if (!list) {
            return std::unexpected{std::move(list).error()};
        }
        return Rhp::from_value<T>(list->empty() ? value{} : list->front());
    }

    static result<void> nothing(result<value>&& r) {
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return {};
    }

    std::optional<signing_key_t> signer_;
#if RHP_ENABLE
    typename Cfg::io_t runner_{};
    std::shared_ptr<client_detail::engine> engine_;
#endif
};

} // namespace Rhp
