#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/client/detail/engine.hpp>
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

#if !defined(RHP_ENABLE)
#define RHP_ENABLE 1
#endif

namespace Rhp {

using wire::module_ref;
using wire::module_status;
using wire::revert_summary;

// Talks to an Rhp::host: authenticates with a credential (a key name + secret for psk_keyring),
// then sends requests and blocks for their results. Script output arrives through
// client_options::on_output / on_emit while a call waits.
//
//   Rhp::client<> c{Rhp::endpoint::dial("127.0.0.1", 7777), Rhp::security::psk_identity{"dev", *key}};
//   auto g = c.exec<double>("return game.gravity");          // Rhp::result<double>
//   auto mod = c.load("low_grav", source);
//   c.call(*mod, "set", 1.6);
//   c.unload(*mod);
//
// Calls may come from any thread (with the default io<owned_io_thread>); cancel() may be called
// while another thread waits. With io<zero_threads> the calling thread runs the network itself,
// so use the client from one thread — and call poll() at least once per heartbeat (2 s by default)
// while idle, or the host drops the session (and reverts what it did) after heartbeat_misses. Destroying the client ends its session: if it was its
// identity's last one, the host reverts everything that identity did. Async calls, rhp-cli and
// signed scripts arrive in Stage 4.
//
// With RHP_ENABLE=0 every call reports kDisabled.
template <configuration Cfg = config<>>
class client {
public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;

    client(net::endpoint ep, typename Cfg::credential_t identity, client_options options = {}) {
#if RHP_ENABLE
        client_detail::setup s;
        s.ep = std::move(ep);
        s.transport = net::transport_ops_for<typename Cfg::transport_t>;
        s.codec = wire::codec_ops_for<typename Cfg::codec_t>;
        s.begin_handshake = [identity = std::move(identity)] { return identity.begin(); };
        s.limits = Cfg::limits_v;
        s.io_thread = Cfg::io_t::kOwnsThread;
        s.options = std::move(options);
        engine_ = client_detail::make_engine(std::move(s));
        if constexpr (Cfg::io_t::kOwnsThread) {
            runner_.start([engine = engine_.get()](std::stop_token stop) { client_detail::run_io(*engine, std::move(stop)); });
        }
#else
        (void)ep;
        (void)identity;
        (void)options;
#endif
    }

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
    // kForbidden (a non-loopback address without insecure_lan), kProtocolRevisionMismatch.
    return_t<void> connect() { return finish(do_connect()); }

    // ---- scripts --------------------------------------------------------------------------------

    // Runs source in this identity's scratch module (effects kept until reverted or disconnect).
    return_t<value_list> exec(std::string_view source, std::string_view chunk = "exec") {
        return finish(values(send(wire::op::kExec, wire::exec_request{std::string{source}, std::string{chunk}})));
    }

    // The first returned value, converted (nil if none).
    template <from_value_convertible T>
    return_t<T> exec(std::string_view source, std::string_view chunk = "exec") {
        auto list = values(send(wire::op::kExec, wire::exec_request{std::string{source}, std::string{chunk}}));
        if (!list) {
            return finish(result<T>{std::unexpected{std::move(list).error()}});
        }
        return finish(Rhp::from_value<T>(list->empty() ? value{} : list->front()));
    }

    return_t<module_id> load(std::string_view name, std::string_view source) {
        return finish(as<module_id>(send(wire::op::kLoad, wire::load_request{std::string{name}, std::string{source}})));
    }

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
        return finish(as<revision_id>(send(wire::op::kReload, wire::reload_request{std::move(mod), std::string{source}})));
    }

    return_t<revision_id> rollback(module_ref mod, std::size_t steps = 1) {
        return finish(as<revision_id>(send(wire::op::kRollback, wire::rollback_request{std::move(mod), steps})));
    }

    return_t<revert_summary> revert(module_ref mod) { return finish(as<revert_summary>(send(wire::op::kRevert, wire::module_request{std::move(mod)}))); }

    // `force` unloads even while other modules require this one (they then get kUnloaded).
    return_t<revert_summary> unload(module_ref mod, bool force = false) {
        return finish(as<revert_summary>(send(wire::op::kUnload, wire::unload_request{std::move(mod), force})));
    }

    return_t<void> checkpoint(std::string_view tag) {
        auto r = send(wire::op::kCheckpoint, wire::tag_request{std::string{tag}});
        if (!r) {
            return finish(result<void>{std::unexpected{std::move(r).error()}});
        }
        return finish(result<void>{});
    }

    return_t<revert_summary> revert_to(std::string_view tag) {
        return finish(as<revert_summary>(send(wire::op::kRevertTo, wire::tag_request{std::string{tag}})));
    }

    // Admin: unloads every module of every identity on the host.
    return_t<revert_summary> revert_all() { return finish(as<revert_summary>(raw(wire::op::kRevertAll, value{}))); }

    // Stops every request this client has in flight (any thread; doesn't wait). The calls waiting
    // for them get kCancelled.
    void cancel() noexcept {
#if RHP_ENABLE
        client_detail::cancel(*engine_);
#endif
    }

    // ---- introspection ------------------------------------------------------------------------------

    return_t<std::vector<module_status>> list() { return finish(as<std::vector<module_status>>(raw(wire::op::kList, value{}))); }

    return_t<module_status> status(module_ref mod) { return finish(as<module_status>(send(wire::op::kStatus, wire::module_request{std::move(mod)}))); }

    // LuaLS annotations for everything this identity can use on the host.
    return_t<std::string> describe() { return finish(as<std::string>(raw(wire::op::kDescribe, value{}))); }

    // io<zero_threads>: handles whatever the network has ready (pings, streamed output) without
    // blocking. Call it from your loop between requests. No-op with an I/O thread.
    void poll() {
#if RHP_ENABLE
        client_detail::poll(*engine_);
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
    template <class T>
    static return_t<T> finish(result<T>&& r) {
        return Cfg::errors_t::finish(std::move(r));
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

#if RHP_ENABLE
    typename Cfg::io_t runner_{};
    client_detail::engine_ptr engine_;
#endif
};

} // namespace Rhp
