#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stop_token>
#include <string_view>
#include <utility>

#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>

#if !defined(RHP_ENABLE)
#define RHP_ENABLE 1
#endif

namespace Rhp {

// A program that accepts remote Lua: it listens on an endpoint, authenticates every connection
// against its authenticator (keys → identities → roles), runs each identity's scripts in that
// identity's own sandbox on the thread that calls pump(), and streams print / rhp.emit / results
// back. When an identity's last session ends, everything it did is reverted and its sandbox closed.
//
//   Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777),
//                    Rhp::security::keyring{{"dev", *Rhp::security::key::from_env("RHP_KEY_DEV"), Rhp::role::kAdmin}}};
//   host.install<game_lib>();
//   while (running) { host.pump(); game::update(); }
//
// pump() is the only thread that touches Lua; the network runs on the config's io policy (an
// RHP-owned thread by default, so cancel and disconnect reach a script stuck inside pump()).
// Stage 3 hosts listen; reverse mode (a host that dials) arrives in Stage 4.
//
// With RHP_ENABLE=0 the host is inert: it never listens, install() and port() report kDisabled.
template <configuration Cfg = config<>>
class host {
public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;

    host(net::endpoint ep, typename Cfg::auth_t auth, host_options options = {}) {
#if RHP_ENABLE
        host_detail::setup s;
        s.ep = std::move(ep);
        s.transport = net::transport_ops_for<typename Cfg::transport_t>;
        s.codec = wire::codec_ops_for<typename Cfg::codec_t>;
        s.begin_handshake = [auth = std::move(auth)] { return auth.begin(); };
        s.limits = Cfg::limits_v;
        s.io_thread = Cfg::io_t::kOwnsThread;
        s.log_enabled = [this](log_level level) { return logger_.enabled(level); };
        s.log = [this](log_level level, std::string_view message) { logger_.write(level, message); };
        s.clock = [this] { return clock_.now(); };
        s.options = options;
        engine_ = host_detail::make_engine(std::move(s));
        if constexpr (Cfg::io_t::kOwnsThread) {
            runner_.start([engine = engine_.get()](std::stop_token stop) { host_detail::run_io(*engine, std::move(stop)); });
        }
#else
        (void)ep;
        (void)auth;
        (void)options;
#endif
    }

    // Stops the network, ends every session and reverts every identity.
    ~host() {
#if RHP_ENABLE
        runner_.stop();
        engine_.reset();
#endif
    }

    host(const host&) = delete;
    host& operator=(const host&) = delete;
    host(host&&) = delete;
    host& operator=(host&&) = delete;

    // Makes a lib visible to every identity's sandbox (those running now and those to come).
    // Call from the pump thread. kAlreadyLoaded if the name is taken.
    template <script::installable L>
    return_t<void> install() {
#if RHP_ENABLE
        return Cfg::errors_t::finish(host_detail::install(*engine_, L::name, &host_detail::install_into<L>));
#else
        return Cfg::errors_t::finish(result<void>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{L::name})});
#endif
    }

    // One frame: runs requests that arrived, resumes suspended scripts, fires timers and queued
    // events, and hands replies to the network. With io<zero_threads> it also polls the network.
    void pump() {
#if RHP_ENABLE
        host_detail::pump(*engine_);
#endif
    }

    // The port the host listens on (the real one after listening on port 0), or why it isn't
    // listening (address in use, a non-loopback address without insecure_lan, ...).
    [[nodiscard]] return_t<std::uint16_t> port() const {
#if RHP_ENABLE
        auto ok = host_detail::listening(*engine_);
        if (!ok) {
            return Cfg::errors_t::finish(result<std::uint16_t>{std::unexpected{std::move(ok).error()}});
        }
        return Cfg::errors_t::finish(result<std::uint16_t>{host_detail::port(*engine_)});
#else
        return Cfg::errors_t::finish(result<std::uint16_t>{fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "host")});
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

    // Identities with a live sandbox (any thread; changes in pump()).
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
#if RHP_ENABLE
    typename Cfg::io_t runner_{};
    host_detail::engine_ptr engine_;
#endif
};

} // namespace Rhp
