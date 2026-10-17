#pragma once

#include <chrono>
#include <concepts>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/client/client.hpp>
#include <rhp/client/detail/fleet_engine.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/discovery.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

// What a broadcast can collect from each host: the raw return values, or one converted value.
template <class T>
concept broadcastable = std::same_as<T, value_list> || from_value_convertible<T>;

template <broadcastable T>
struct host_result {
    net::service_record host;
    result<T> outcome;
};

// Browses with Cfg::discovery_t for options.duration (on the caller's thread) and returns the
// records of hosts a client<Cfg> can talk to: this transport's service and wire revision.
// `while_browsing` runs between network turns (a zero-thread fleet keeps its members alive with it).
template <configuration Cfg, std::invocable F>
[[nodiscard]] result<std::vector<net::service_record>> discover(net::browse_options options, F&& while_browsing) {
#if RHP_ENABLE
    if (options.service.empty() || options.service == net::dns_sd_service("tcp")) {
        options.service = std::string{net::dns_sd_service(Cfg::transport_t::name)};
    }
    if (options.protocol_revision == 0) {
        options.protocol_revision = wire::kProtocolRevision;
    }
    net::io_context io;
    auto browser = Cfg::discovery_t::start_browse(io, options);
    if (!browser) {
        return std::unexpected{std::move(browser).error()};
    }
    const auto until = std::chrono::steady_clock::now() + options.duration;
    while (std::chrono::steady_clock::now() < until) {
        std::invoke(while_browsing);
        io.run_one_for(std::chrono::milliseconds{5});
    }
    return (*browser)->services();
#else
    (void)options;
    (void)while_browsing;
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "fleet.discover");
#endif
}

template <configuration Cfg = config<>>
[[nodiscard]] result<std::vector<net::service_record>> discover(net::browse_options options = {}) {
    return discover<Cfg>(std::move(options), [] {});
}

// A group of hosts addressed together. A broadcast (exec, load, call) starts the request on every
// member, then collects one outcome per host, in member order, within the shared deadline
// (fleet_options::timeout): a slow or failed host never hides the others, and one that missed the
// deadline gets kTimeout (its request is cancelled). Members keep their authenticated sessions and
// effects between broadcasts; one whose session closed for good is replaced on the next broadcast
// or discovery; clear() or destruction ends them.
//
// Every member runs on the fleet's one network reactor: one I/O thread for the whole fleet with
// io<owned_io_thread>, none with io<zero_threads> (then the broadcasts and discover() run it, and
// poll() does while idle). The fleet itself is used from one thread. client_options callbacks
// (on_output, on_emit) run on the network thread: never call the fleet from them.
//
// With RHP_ENABLE=0 every outcome is kDisabled.
template <configuration Cfg = config<>>
class fleet {
public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;
    using signing_key_t = typename Cfg::signing_key_t;

    explicit fleet(typename Cfg::credential_t identity, fleet_options options = {}) : fleet(std::move(identity), std::nullopt, std::move(options)) {}
    fleet(typename Cfg::credential_t identity, signing_key_t signing, fleet_options options = {})
        : fleet(std::move(identity), std::optional<signing_key_t>{std::move(signing)}, std::move(options)) {}

    ~fleet() {
#if RHP_ENABLE
        fleet_detail::close(*engine_);
        runner_.stop();
        engine_.reset();
#endif
    }

    fleet(const fleet&) = delete;
    fleet& operator=(const fleet&) = delete;
    fleet(fleet&&) = delete;
    fleet& operator=(fleet&&) = delete;

    // Browses and adds every compatible host not already a member; returns how many were added.
    // Malformed or foreign records from the network are skipped, not errors.
    return_t<std::size_t> discover(net::browse_options options = {}) {
        auto found = Rhp::discover<Cfg>(std::move(options), [this] { poll(); });
        if (!found) {
            return finish(result<std::size_t>{std::unexpected{std::move(found).error()}});
        }
        std::size_t added = 0;
        for (auto& record : *found) {
            if (fleet_detail::compatible(record, Cfg::transport_t::name)) {
                added += join(std::move(record)) ? 1 : 0;
            }
        }
        return finish(result<std::size_t>{added});
    }

    // Adds one host by hand (or refreshes the member at the same address and port).
    return_t<void> add(net::service_record record) {
        if (!fleet_detail::compatible(record, Cfg::transport_t::name)) {
            return finish(result<void>{fail(errc::kInvalidArgument, "the record needs an address, a port, this transport and this wire revision", "fleet.add")});
        }
        (void)join(std::move(record));
        return finish(result<void>{});
    }

    [[nodiscard]] std::size_t size() const noexcept {
#if RHP_ENABLE
        return fleet_detail::size(*engine_);
#else
        return records_.size();
#endif
    }

    void clear() {
#if RHP_ENABLE
        fleet_detail::clear(*engine_);
#else
        records_.clear();
#endif
    }

    // Drives every member's network under io<zero_threads> (no-op otherwise).
    void poll() {
#if RHP_ENABLE
        fleet_detail::poll(*engine_);
#endif
    }

    // ---- broadcasts --------------------------------------------------------------------------------

    // Runs source in each member's scratch module (as client::exec): the returned values, or the first one converted.
    template <broadcastable T = value_list>
    [[nodiscard]] std::vector<host_result<T>> exec(std::string_view source) {
#if RHP_ENABLE
        return returned<T>(fleet_detail::exec(*engine_, source));
#else
        (void)source;
        return disabled<T>("fleet.exec");
#endif
    }

    // Loads (signed) the module on every member: each host's own module id.
    [[nodiscard]] std::vector<host_result<module_id>> load(std::string_view name, std::string_view source) {
#if RHP_ENABLE
        auto raw = fleet_detail::load(*engine_, name, source);
        std::vector<host_result<module_id>> out;
        out.reserve(raw.size());
        for (auto& o : raw) {
            out.push_back({std::move(o.host), o.body ? Rhp::from_value<module_id>(*o.body) : result<module_id>{std::unexpected{std::move(o.body).error()}}});
        }
        return out;
#else
        (void)name;
        (void)source;
        return disabled<module_id>("fleet.load");
#endif
    }

    // Calls a function of the module named `module` on every member (by name: its id differs per host).
    template <broadcastable T = value_list>
    [[nodiscard]] std::vector<host_result<T>> call(std::string_view module, std::string_view function, std::span<const value> args = {}) {
#if RHP_ENABLE
        return returned<T>(fleet_detail::call(*engine_, module, function, args));
#else
        (void)module;
        (void)function;
        (void)args;
        return disabled<T>("fleet.call");
#endif
    }

    template <broadcastable T = value_list, to_value_convertible A0, to_value_convertible... A>
    [[nodiscard]] std::vector<host_result<T>> call(std::string_view module, std::string_view function, const A0& a0, const A&... rest) {
        const value args[] = {Rhp::to_value(a0), Rhp::to_value(rest)...};
        return call<T>(module, function, std::span<const value>{args});
    }

private:
    fleet(typename Cfg::credential_t identity, std::optional<signing_key_t> signing, fleet_options options) {
#if RHP_ENABLE
        fleet_detail::setup s;
        s.member.transport = net::transport_ops_for<typename Cfg::transport_t>;
        s.member.tls = security::tls::backend_ops_for<typename Cfg::tls_t>;
        s.member.codec = wire::codec_ops_for<typename Cfg::codec_t>;
        s.member.begin_handshake = [identity = std::move(identity)] { return identity.begin(); };
        s.member.limits = Cfg::limits_v;
        s.member.io_thread = Cfg::io_t::kOwnsThread;
        s.member.options = std::move(options.client);
        if (signing) {
            s.sign = [key = std::move(*signing)](std::string_view source) -> result<value> { return key.sign(source); };
        }
        s.transport = std::string{Cfg::transport_t::name};
        s.timeout = options.timeout;
        s.tls = options.tls;
        s.insecure_lan = options.insecure_lan;
        engine_ = fleet_detail::make_engine(std::move(s));
        if constexpr (Cfg::io_t::kOwnsThread) {
            runner_.start([engine = engine_.get()](std::stop_token stop) { fleet_detail::run_io(*engine, std::move(stop)); });
        }
#else
        (void)identity;
        (void)signing;
        (void)options;
#endif
    }

    template <class T>
    static return_t<T> finish(result<T>&& r) {
        return Cfg::errors_t::finish(std::move(r));
    }

    // True when the (compatible) record is a new member.
    bool join(net::service_record record) {
#if RHP_ENABLE
        auto joined = fleet_detail::join(*engine_, std::move(record));
        return joined && *joined;
#else
        for (auto& r : records_) {
            if (r.address == record.address && r.port == record.port) {
                r = std::move(record);
                return false;
            }
        }
        records_.push_back(std::move(record));
        return true;
#endif
    }

#if RHP_ENABLE
    template <broadcastable T>
    static std::vector<host_result<T>> returned(std::vector<fleet_detail::outcome>&& raw) {
        std::vector<host_result<T>> out;
        out.reserve(raw.size());
        for (auto& o : raw) {
            auto list = fleet_detail::values(std::move(o.body));
            if constexpr (std::same_as<T, value_list>) {
                out.push_back({std::move(o.host), std::move(list)});
            } else if (!list) {
                out.push_back({std::move(o.host), std::unexpected{std::move(list).error()}});
            } else {
                out.push_back({std::move(o.host), Rhp::from_value<T>(list->empty() ? value{} : list->front())});
            }
        }
        return out;
    }

    typename Cfg::io_t runner_{};
    fleet_detail::engine_ptr engine_;
#else
    template <broadcastable T>
    std::vector<host_result<T>> disabled(const char* where) const {
        std::vector<host_result<T>> out;
        out.reserve(records_.size());
        for (const auto& r : records_) {
            out.push_back({r, fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", where)});
        }
        return out;
    }

    std::vector<net::service_record> records_;
#endif
};

} // namespace Rhp
