#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/client/detail/engine.hpp>
#include <rhp/client/detail/fleet_engine.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::fleet_detail {

namespace {

using clock = std::chrono::steady_clock;

// While a zero_threads fleet waits, it runs the reactor in slices this long.
constexpr std::chrono::milliseconds kPollSlice{5};
// Bounds the handlers a teardown runs to finish work still queued (retired members).
constexpr int kDrainRounds = 64;

// One broadcast's outcomes. They arrive on the I/O thread (or inside the waits with zero_threads,
// or at once on the caller's thread for a member that is already closed).
struct collector {
    explicit collector(std::size_t n) : outcomes(n) {}

    void complete(std::size_t i, result<value> r) {
        {
            const std::scoped_lock lock{mutex};
            if (collected || outcomes[i]) {
                return; // late (the deadline passed) or a duplicate
            }
            outcomes[i] = std::move(r);
            ++done;
        }
        changed.notify_all();
    }

    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::optional<result<value>>> outcomes;
    std::size_t done = 0;
    bool collected = false;
};

} // namespace

class engine {
public:
    explicit engine(setup s) : setup_(std::move(s)) {}

    ~engine() {
        // The I/O thread is stopped (or there never was one): finish what is still queued for the
        // reactor (retired members' teardown), then the members go, then the reactor.
        drain();
        members_.clear();
        drain();
    }

    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;

    result<bool> join(net::service_record record) {
        if (!compatible(record, setup_.transport)) {
            return fail(errc::kInvalidArgument, "the record needs an address, a port, this transport and this wire revision", "fleet.add");
        }
        for (auto& m : members_) {
            if (m.record.address == record.address && m.record.port == record.port) {
                m.record = std::move(record);
                refresh(m);
                return false;
            }
        }
        auto connection = make_member(record);
        members_.push_back(member{std::move(record), std::move(connection)});
        return true;
    }

    [[nodiscard]] std::size_t size() const noexcept { return members_.size(); }

    void clear() {
        auto members = std::move(members_);
        members_.clear();
        for (auto& m : members) {
            retire(std::move(m.connection));
        }
    }

    void poll() {
        if (!setup_.member.io_thread) {
            io_.poll();
        }
    }

    void close() noexcept {
        for (auto& m : members_) {
            client_detail::close(*m.connection);
        }
    }

    void run_io(std::stop_token stop) { io_.run(std::move(stop)); }

    std::vector<outcome> exec(std::string_view source) {
        return broadcast(wire::op::kExec, code_body(source, [&](value signature) { return Rhp::to_value(wire::exec_request{std::string{source}, "exec", std::move(signature)}); }),
                         "fleet.exec");
    }

    std::vector<outcome> load(std::string_view name, std::string_view source) {
        return broadcast(wire::op::kLoad,
                         code_body(source, [&](value signature) { return Rhp::to_value(wire::load_request{std::string{name}, std::string{source}, std::move(signature)}); }),
                         "fleet.load");
    }

    std::vector<outcome> call(std::string_view module, std::string_view function, std::span<const value> args) {
        // By name: a module's id differs from host to host.
        const wire::module_ref target{std::string{module}};
        return broadcast(wire::op::kCall, Rhp::to_value(wire::call_request{target, std::string{function}, value::array(args.begin(), args.end())}), "fleet.call");
    }

private:
    struct member {
        net::service_record record;
        client_detail::engine_ptr connection;
    };

    // A code-carrying body (exec / load) with the source's signature, or why it couldn't be signed.
    template <class Make>
    result<value> code_body(std::string_view source, Make make) const {
        value signature;
        if (setup_.sign) {
            auto signed_by = setup_.sign(source);
            if (!signed_by) {
                return std::unexpected{std::move(signed_by).error()};
            }
            signature = std::move(*signed_by);
        }
        return make(std::move(signature));
    }

    [[nodiscard]] client_detail::engine_ptr make_member(const net::service_record& record) {
        client_detail::setup s = setup_.member;
        s.ep = net::endpoint::dial(record.address, record.port);
        s.ep.tls = setup_.tls;
        s.ep.insecure_lan = setup_.insecure_lan;
        s.shared_io = &io_;
        return client_detail::make_engine(std::move(s));
    }

    // A member whose client closed for good gets a fresh one (a resumable detach keeps its session).
    void refresh(member& m) {
        if (client_detail::info(*m.connection).closed) {
            retire(std::exchange(m.connection, make_member(m.record)));
        }
    }

    // Ends a member's session and destroys its engine where the reactor runs: inline when this
    // thread is the only one running it, otherwise on the I/O thread (FIFO after what the engine
    // already queued there).
    void retire(client_detail::engine_ptr old) {
        if (old == nullptr) {
            return;
        }
        client_detail::close(*old);
        if (!setup_.member.io_thread) {
            old.reset();
            return;
        }
        auto holder = std::make_shared<client_detail::engine_ptr>(std::move(old));
        io_.post([holder] { holder->reset(); });
    }

    void drain() {
        for (int round = 0; round < kDrainRounds && io_.poll() != 0; ++round) {
        }
    }

    std::vector<outcome> broadcast(wire::op code, result<value> body, std::string_view where) {
        std::vector<std::size_t> all(members_.size());
        for (std::size_t i = 0; i < all.size(); ++i) {
            all[i] = i;
        }
        return send_to(code, std::move(body), all, where);
    }

public:
    [[nodiscard]] std::vector<net::service_record> records() const {
        std::vector<net::service_record> out;
        out.reserve(members_.size());
        for (const auto& m : members_) {
            out.push_back(m.record);
        }
        return out;
    }

    // The request on the members at `which` (indices into records()), one outcome each, in that order.
    std::vector<outcome> send_to(wire::op code, result<value> body, std::span<const std::size_t> which, std::string_view where) {
        std::vector<outcome> out;
        out.reserve(which.size());
        for (const std::size_t i : which) {
            if (i < members_.size()) {
                refresh(members_[i]);
            }
        }
        if (!body) {
            for (const std::size_t i : which) {
                out.push_back({i < members_.size() ? members_[i].record : net::service_record{}, std::unexpected{body.error()}});
            }
            return out;
        }
        auto pending = std::make_shared<collector>(which.size());
        std::vector<std::uint64_t> requests(which.size(), 0);
        for (std::size_t k = 0; k < which.size(); ++k) {
            if (which[k] >= members_.size()) {
                pending->complete(k, fail(errc::kNotFound, "no such fleet member", std::string{where}));
                continue;
            }
            requests[k] = client_detail::submit(*members_[which[k]].connection, code, *body, [pending, k](result<value> r) { pending->complete(k, std::move(r)); });
        }
        wait(*pending);
        std::vector<std::optional<result<value>>> outcomes;
        {
            const std::scoped_lock lock{pending->mutex};
            pending->collected = true;
            outcomes = std::move(pending->outcomes);
        }
        for (std::size_t k = 0; k < which.size(); ++k) {
            const bool known = which[k] < members_.size();
            if (!outcomes[k]) {
                if (known) {
                    client_detail::cancel(*members_[which[k]].connection, requests[k]);
                }
                outcomes[k] = fail(errc::kTimeout, "the host missed the broadcast deadline", std::string{where});
            }
            out.push_back({known ? members_[which[k]].record : net::service_record{}, std::move(*outcomes[k])});
        }
        return out;
    }

private:
    // Until every member answered or the shared deadline passed. With zero_threads nobody else
    // runs the reactor: this thread runs every member's network meanwhile.
    void wait(collector& pending) {
        const bool bounded = setup_.timeout.count() != 0;
        const auto deadline = clock::now() + setup_.timeout;
        const auto finished = [&pending] { return pending.done == pending.outcomes.size(); };
        if (setup_.member.io_thread) {
            std::unique_lock lock{pending.mutex};
            if (bounded) {
                (void)pending.changed.wait_until(lock, deadline, finished);
            } else {
                pending.changed.wait(lock, finished);
            }
            return;
        }
        for (;;) {
            {
                const std::scoped_lock lock{pending.mutex};
                if (finished()) {
                    return;
                }
            }
            auto slice = kPollSlice;
            if (bounded) {
                const auto now = clock::now();
                if (now >= deadline) {
                    return;
                }
                slice = std::min(slice, std::chrono::ceil<std::chrono::milliseconds>(deadline - now));
            }
            io_.run_one_for(slice);
        }
    }

    setup setup_;
    net::io_context io_; // every member's: declared before them so it outlives them
    std::vector<member> members_;
};

// ---- the C++ wall --------------------------------------------------------------------------------------

void engine_deleter::operator()(engine* e) const noexcept {
    delete e;
}

engine_ptr make_engine(setup s) {
    return engine_ptr{new engine{std::move(s)}};
}

result<bool> join(engine& e, net::service_record record) {
    return e.join(std::move(record));
}

std::size_t size(const engine& e) noexcept {
    return e.size();
}

void clear(engine& e) {
    e.clear();
}

void poll(engine& e) {
    e.poll();
}

void close(engine& e) noexcept {
    e.close();
}

void run_io(engine& e, std::stop_token stop) {
    e.run_io(std::move(stop));
}

std::vector<outcome> exec(engine& e, std::string_view source) {
    return e.exec(source);
}

std::vector<outcome> load(engine& e, std::string_view name, std::string_view source) {
    return e.load(name, source);
}

std::vector<outcome> call(engine& e, std::string_view module, std::string_view function, std::span<const value> args) {
    return e.call(module, function, args);
}

std::vector<net::service_record> records(const engine& e) {
    return e.records();
}

std::vector<outcome> send(engine& e, wire::op code, const value& body, std::span<const std::size_t> which) {
    return e.send_to(code, body, which, wire::to_string(code));
}

} // namespace Rhp::fleet_detail
