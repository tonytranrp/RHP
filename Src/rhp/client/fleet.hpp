#pragma once

#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/client/client.hpp>
#include <rhp/net/discovery.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

// What a broadcast can collect from each host: the raw return values, or one converted value.
template <class T>
concept broadcastable = std::same_as<T, value_list> || from_value_convertible<T>;

struct fleet_options {
    client_options client{};
    std::chrono::milliseconds timeout{10000}; // per broadcast, shared by every host; zero waits without a deadline
    net::tls_mode tls = net::tls_mode::kAuto;
    bool insecure_lan = false; // the caller's opt-in only: never taken from discovery records
};

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

// A group of hosts addressed together: exec() starts the script on every member, then collects
// one outcome per host within the shared deadline (a slow or failed host never hides the others).
// Members keep their authenticated sessions and effects between broadcasts; clear() or
// destruction ends them. One caller thread.
template <configuration Cfg = config<>>
class fleet {
    using member_cfg = typename Cfg::template errors<errors::expected>;
    using member_client = client<member_cfg>;

public:
    template <class T>
    using return_t = typename Cfg::template return_t<T>;

    explicit fleet(typename Cfg::credential_t identity, fleet_options options = {}) : identity_(std::move(identity)), options_(std::move(options)) {}
    fleet(typename Cfg::credential_t identity, typename Cfg::signing_key_t signing, fleet_options options = {})
        : identity_(std::move(identity)), signing_(std::move(signing)), options_(std::move(options)) {}

    fleet(const fleet&) = delete;
    fleet& operator=(const fleet&) = delete;

    // Browses and adds every compatible host not already a member; returns how many were added.
    // Malformed or foreign records from the network are skipped, not errors.
    return_t<std::size_t> discover(net::browse_options options = {}) {
        auto found = Rhp::discover<Cfg>(std::move(options), [this] { poll(); });
        if (!found) {
            return Cfg::errors_t::finish(result<std::size_t>{std::unexpected{std::move(found).error()}});
        }
        std::size_t added = 0;
        for (auto& record : *found) {
            if (compatible(record)) {
                added += join(std::move(record)) ? 1 : 0;
            }
        }
        return Cfg::errors_t::finish(result<std::size_t>{added});
    }

    // Adds one host by hand (or refreshes the member at the same address and port).
    return_t<void> add(net::service_record record) {
        if (!compatible(record)) {
            return Cfg::errors_t::finish(result<void>{fail(errc::kInvalidArgument, "the record needs an address, a port, this transport and this wire revision", "fleet.add")});
        }
        (void)join(std::move(record));
        return Cfg::errors_t::finish(result<void>{});
    }

    [[nodiscard]] std::size_t size() const noexcept { return members_.size(); }
    void clear() { members_.clear(); }

    // Drives every member's network under io<zero_threads> (no-op otherwise).
    void poll() {
        for (auto& m : members_) {
            m.connection->poll();
        }
    }

    template <broadcastable T = value_list>
    [[nodiscard]] std::vector<host_result<T>> exec(std::string_view source) {
        auto pending = std::make_shared<collector<T>>(members_.size());
        std::vector<std::uint64_t> requests;
        requests.reserve(members_.size());
        for (std::size_t i = 0; i < members_.size(); ++i) {
            auto& m = members_[i];
            if (m.connection->info().closed) {
                m.connection = make_client(m.record); // a resumable detach keeps its session; a closed one can't
            }
            auto call = [&] {
                if constexpr (std::same_as<T, value_list>) {
                    return m.connection->async().exec(source);
                } else {
                    return m.connection->async().template exec<T>(source);
                }
            }();
            requests.push_back(call.request());
            std::move(call).then([pending, i](result<T> outcome) { pending->complete(i, std::move(outcome)); });
        }
        wait(*pending);
        std::vector<host_result<T>> out;
        out.reserve(members_.size());
        for (std::size_t i = 0; i < members_.size(); ++i) {
            auto outcome = pending->take(i);
            if (!outcome) {
                members_[i].connection->cancel(requests[i]);
                outcome = fail(errc::kTimeout, "the host missed the broadcast deadline", "fleet.exec");
            }
            out.push_back({members_[i].record, std::move(*outcome)});
        }
        return out;
    }

private:
    struct member {
        net::service_record record;
        std::unique_ptr<member_client> connection;
    };

    // Outcomes arrive on the members' network threads.
    template <class T>
    struct collector {
        explicit collector(std::size_t n) : outcomes(n) {}

        void complete(std::size_t i, result<T> outcome) {
            {
                const std::scoped_lock lock{mutex};
                if (outcomes[i]) {
                    return;
                }
                outcomes[i] = std::move(outcome);
                ++done;
            }
            changed.notify_all();
        }

        [[nodiscard]] std::optional<result<T>> take(std::size_t i) {
            const std::scoped_lock lock{mutex};
            return std::exchange(outcomes[i], std::nullopt);
        }

        std::mutex mutex;
        std::condition_variable changed;
        std::vector<std::optional<result<T>>> outcomes;
        std::size_t done = 0;
    };

    template <class T>
    void wait(collector<T>& pending) {
        const bool bounded = options_.timeout.count() != 0;
        const auto deadline = std::chrono::steady_clock::now() + options_.timeout;
        const auto finished = [&] { return pending.done == pending.outcomes.size(); };
        if constexpr (Cfg::io_t::kOwnsThread) {
            std::unique_lock lock{pending.mutex};
            if (bounded) {
                (void)pending.changed.wait_until(lock, deadline, finished);
            } else {
                pending.changed.wait(lock, finished);
            }
        } else {
            // Nobody else runs the members' networks: progress them here.
            for (;;) {
                poll();
                {
                    const std::scoped_lock lock{pending.mutex};
                    if (finished() || (bounded && std::chrono::steady_clock::now() >= deadline)) {
                        return;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }
    }

    [[nodiscard]] static bool compatible(const net::service_record& record) noexcept {
        return record.port != 0 && !record.address.empty() && record.protocol_revision == wire::kProtocolRevision && record.transport == Cfg::transport_t::name;
    }

    // True when the record is a new member.
    bool join(net::service_record record) {
        for (auto& m : members_) {
            if (m.record.address == record.address && m.record.port == record.port) {
                m.record = std::move(record);
                if (m.connection->info().closed) {
                    m.connection = make_client(m.record);
                }
                return false;
            }
        }
        auto connection = make_client(record);
        members_.push_back(member{std::move(record), std::move(connection)});
        return true;
    }

    [[nodiscard]] std::unique_ptr<member_client> make_client(const net::service_record& record) const {
        auto ep = endpoint::dial(record.address, record.port);
        ep.tls = options_.tls;
        ep.insecure_lan = options_.insecure_lan;
        if (signing_) {
            return std::make_unique<member_client>(ep, identity_, *signing_, options_.client);
        }
        return std::make_unique<member_client>(ep, identity_, options_.client);
    }

    typename Cfg::credential_t identity_;
    std::optional<typename Cfg::signing_key_t> signing_;
    fleet_options options_;
    std::vector<member> members_;
};

} // namespace Rhp
