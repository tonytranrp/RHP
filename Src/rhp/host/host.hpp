#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <rhp/build_config.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/event/hub.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/host/detail/releases.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>

namespace Rhp {

// A program that accepts remote Lua: it listens on an endpoint (or, in reverse mode, dials one),
// authenticates every connection against its authenticator (keys -> identities -> roles), checks
// every script's signature against its trusted signers, runs each identity's scripts in that
// identity's own sandbox on the thread that calls pump(), and streams print / rhp.emit / results
// back. When an identity's last session ends, everything it did is reverted and its sandbox closed
// - except modules an admin pinned.
//
//   Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777),
//                    Rhp::security::keyring{{"dev", *Rhp::security::key::from_env("RHP_KEY_DEV"), Rhp::role::kAdmin}},
//                    *Rhp::security::trusted_signers::from_file("rhp_signers.pub")};
//   host.install<game_lib>();
//   auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
//   while (running) { host.pump(); game::update(); }
//
// Scripts (exec / load / reload) must be signed by a trusted signer, except from observe sessions;
// `config<>::signer<Rhp::security::unsigned_scripts>` turns signing off. pump() is the only thread
// that touches Lua; the network runs on the config's io policy (an RHP-owned thread by default, so
// cancel and disconnect reach a script stuck inside pump()).
//
// Reverse mode: with Rhp::endpoint::dial(...) the host dials a listening client (a phone dialing
// the developer's PC) and dials again, with capped exponential backoff and full jitter, whenever
// that fails or the session ends.
//
// With RHP_ENABLE=0 the host is inert: it never listens, and every result-bearing call reports kDisabled.
template <configuration Cfg = config<>>
class host {
public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;

    host(net::endpoint ep, typename Cfg::auth_t auth, typename Cfg::trust_t trust, host_options options = {}) {
#if RHP_ENABLE
        host_detail::setup s;
        s.ep = std::move(ep);
        s.transport = net::transport_ops_for<typename Cfg::transport_t>;
        s.tls = security::tls::backend_ops_for<typename Cfg::tls_t>;
        s.codec = wire::codec_ops_for<typename Cfg::codec_t>;
        s.discovery = net::discovery_ops_for<typename Cfg::discovery_t>;
        if constexpr (security::http_authenticator<typename Cfg::auth_t>) {
            s.http_auth = [auth](const security::http_proof& request, std::chrono::system_clock::time_point now) { return auth.verify_http(request, now); };
        }
        s.begin_handshake = [auth = std::move(auth)] { return auth.begin(); };
        s.verify = [trust = std::move(trust)](std::string_view source, const value& signature) { return trust.verify(source, signature); };
        s.events = events_;
        s.script_events = script_events_;
        s.limits = Cfg::limits_v;
        s.io_thread = Cfg::io_t::kOwnsThread;
        if constexpr (!std::is_same_v<typename Cfg::logger_t, core::null_logger>) { // null_logger: no calls at all
            s.log_enabled = [this](log_level level) { return logger_.enabled(level); };
            s.log = [this](log_level level, std::string_view message) { logger_.write(level, message); };
        }
        s.clock = [this] { return clock_.now(); };
        s.custom_clock = !std::is_same_v<typename Cfg::clock_t, exec::steady_clock>;
        s.options = options;
        engine_ = host_detail::make_engine(std::move(s));
        if constexpr (Cfg::io_t::kOwnsThread) {
            runner_.start([engine = engine_.get()](std::stop_token stop) { host_detail::run_io(*engine, std::move(stop)); });
        }
#else
        (void)ep;
        (void)auth;
        (void)trust;
        (void)options;
#endif
    }

    // No trusted signers: only observe sessions can run code (unless the config's signer is
    // Rhp::security::unsigned_scripts).
    host(net::endpoint ep, typename Cfg::auth_t auth, host_options options = {}) : host(std::move(ep), std::move(auth), typename Cfg::trust_t{}, options) {}

    // Stops the network, ends every session and reverts every identity (pinned modules included).
    ~host() {
#if RHP_ENABLE
        host_detail::goodbye(*engine_);
        runner_.stop();
        engine_.reset();
#endif
    }

    host(const host&) = delete;
    host& operator=(const host&) = delete;
    host(host&&) = delete;
    host& operator=(host&&) = delete;

    // Makes a lib visible to every identity's sandbox (those running now and those to come).
    // Call from the pump thread (any one thread before the first pump(); from another thread after it:
    // kInvalidArgument). kAlreadyLoaded if the name is taken.
    template <script::installable L>
    return_t<void> install() {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::install(*engine_, L::name, &host_detail::install_into<L>));
#else
        return Cfg::errors_t::finish(result<void>{host_detail::compiled_out(L::name)});
#endif
    }

    // Registers a blob sink: clients push files to it (client.blob("configs", bytes)). The whole
    // blob (at most limits.max_blob) is handed over once it arrived, on the pump thread; the
    // sink's result is the client's answer. `need` is the least role that may send to it.
    // Call from the pump thread (any one thread before the first pump(); from another thread after it:
    // kInvalidArgument). kAlreadyLoaded if the name is taken.
    return_t<void> on_blob(std::string_view sink, blob_fn fn, role need = role::kAdmin) {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::add_blob_sink(*engine_, sink, std::move(fn), need));
#else
        (void)fn;
        (void)need;
        return Cfg::errors_t::finish(result<void>{host_detail::compiled_out(sink)});
#endif
    }

    // Serves a release manager: clients apply, confirm and deactivate releases (admin) and read
    // their status or send revocation lists (observe) through it, and pump() pumps it (with every
    // release_changed reported as a host event). The manager must outlive the host. Call from the
    // pump thread. kAlreadyLoaded if one is served already.
    return_t<void> serve(release::manager& releases) {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::serve_releases(*engine_, host_detail::bridge(releases)));
#else
        (void)releases;
        return Cfg::errors_t::finish(result<void>{host_detail::compiled_out("host.serve")});
#endif
    }

    // Calls `fn` for every event of type E (Rhp::event::script_executed, session_opened, ...) until
    // the returned subscription dies. Events are reported on the pump thread.
    template <event::host_event E, std::invocable<const E&> F>
    [[nodiscard]] event::subscription on(F fn) {
        return event::subscribe<E>(events_, std::move(fn));
    }

    // Every event (an Rhp::event::any): what the audit sinks take.
    template <std::invocable<const event::any&> F>
    [[nodiscard]] event::subscription on_any(F fn) {
        return event::subscribe_any(events_, std::move(fn));
    }

    // Calls `fn` for every rhp.publish of `name` ("*": every name, rhp.handler_failed included) in
    // any identity's sandbox, on the pump thread, until the returned subscription dies.
    template <std::invocable<const event::script_event&> F>
    [[nodiscard]] event::subscription on_script_event(std::string_view name, F fn) {
        return event::subscribe_script(script_events_, name, std::move(fn));
    }

    // One frame: runs requests that arrived, resumes suspended scripts, fires timers and queued
    // events, and hands replies to the network. With io<zero_threads> it also polls the network.
    void pump() {
#if RHP_ENABLE
        host_detail::pump(*engine_);
#endif
    }

    // Runtime kill switch (any thread). While off, new connections are closed and every request is
    // answered kDisabled; what already ran stays (send revert_all first to undo it).
    void set_enabled(bool on) noexcept {
#if RHP_ENABLE
        host_detail::set_enabled(*engine_, on);
#else
        (void)on;
#endif
    }

    [[nodiscard]] bool enabled() const noexcept {
#if RHP_ENABLE
        return host_detail::enabled(*engine_);
#else
        return false;
#endif
    }

    // The port the host listens on (the real one after listening on port 0; 0 in reverse mode), or
    // why it isn't listening (address in use, a non-loopback address without insecure_lan, ...).
    [[nodiscard]] return_t<std::uint16_t> port() const {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::port(*engine_));
#else
        return Cfg::errors_t::finish(result<std::uint16_t>{host_detail::compiled_out("host")});
#endif
    }

    // The HTTP listener's port (host_options::gateway; useful after asking for port 0), or why it
    // isn't listening. Any thread.
    [[nodiscard]] return_t<std::uint16_t> gateway_port() const {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::gateway_port(*engine_));
#else
        return Cfg::errors_t::finish(result<std::uint16_t>{host_detail::compiled_out("host.gateway")});
#endif
    }

    // Publishes this host through Cfg::discovery_t (DNS-SD by default). Nothing is published until
    // this is called; calling it again updates the record. Pump thread (kInvalidArgument from another
    // thread once pump() ran), after installing libraries (options.include_libs publishes their
    // names). Later provider errors: discovery_status().
    return_t<void> advertise(net::advertise_options options = {}) {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::advertise(*engine_, std::move(options)));
#else
        (void)options;
        return Cfg::errors_t::finish(result<void>{host_detail::compiled_out("host.discovery")});
#endif
    }

    // The advertisement's state: kAlreadyLoaded after a name conflict, kDisabled when not advertising.
    // Any thread with the default owned I/O thread; the pump thread with io<zero_threads>.
    [[nodiscard]] return_t<void> discovery_status() {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::discovery_status(*engine_));
#else
        return Cfg::errors_t::finish(result<void>{host_detail::compiled_out("host.discovery")});
#endif
    }

    // Authenticated sessions right now (any thread).
    [[nodiscard]] std::size_t sessions() const noexcept {
#if RHP_ENABLE
        return host_detail::sessions(*engine_);
#else
        return 0;
#endif
    }

    // Identities with a live sandbox (any thread; changes in pump()). An identity whose sessions
    // are gone but which has pinned modules still counts.
    [[nodiscard]] std::size_t identities() const noexcept {
#if RHP_ENABLE
        return host_detail::identities(*engine_);
#else
        return 0;
#endif
    }

    [[nodiscard]] typename Cfg::logger_t& logger() noexcept { return logger_; }
    [[nodiscard]] typename Cfg::clock_t& clock() noexcept { return clock_; }

private:
    typename Cfg::logger_t logger_{};
    typename Cfg::clock_t clock_{};
    std::shared_ptr<event::hub> events_ = std::make_shared<event::hub>();
    std::shared_ptr<event::script_hub> script_events_ = std::make_shared<event::script_hub>();
#if RHP_ENABLE
    typename Cfg::io_t runner_{};
    host_detail::engine_ptr engine_;
#endif
};

} // namespace Rhp
