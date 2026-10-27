#include <chrono>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/net/link.hpp>
#include <rhp/session/admission.hpp>

namespace Rhp::session {

namespace {

constexpr const char* kWhere = "admission";

// Notes the first byte the peer sends (before TLS: a ClientHello counts) and passes everything on.
class watched_link final : public net::link_decorator, private net::link_handler {
public:
    watched_link(std::unique_ptr<net::link> inner, std::shared_ptr<bool> heard) : link_decorator(std::move(inner)), heard_(std::move(heard)) {}

    void start(net::link_handler& handler) override {
        handler_ = &handler;
        inner().start(*this);
    }

private:
    void on_bytes(utils::bytes_view data) override {
        if (!data.empty() && heard_ != nullptr) {
            *heard_ = true;
            heard_.reset();
        }
        handler_->on_bytes(data);
    }

    void on_closed(const error& why) override { handler_->on_closed(why); }

    std::shared_ptr<bool> heard_;
    net::link_handler* handler_ = nullptr;
};

} // namespace

admission::admission(net::io_context& io, const Rhp::limits& limits)
    : io_(io),
      total_cap_(limits.pending_handshakes),
      source_cap_(limits.handshakes_per_source),
      first_byte_(limits.first_byte_ms),
      timer_(io) {}

admission::~admission() {
    timer_.cancel();
}

result<admission::ticket> admission::admit(std::unique_ptr<net::link>& link, close_fn close) {
    if (total_cap_ == 0) {
        return fail(errc::kLimitExceeded, "this side accepts no connections (limits.pending_handshakes is 0)", kWhere);
    }
    std::optional<net::ip_address> source;
    if (const auto ip = link->address()) {
        source = ip->source();
    }
    if (source && source_cap_ != 0) {
        const auto count = per_source_.find(*source);
        if (count != per_source_.end() && count->second >= source_cap_ &&
            !make_room(source, make_error(errc::kLimitExceeded, std::format("closed to make room: it sent nothing while {} connections from its source were waiting", source_cap_), kWhere))) {
            return fail(errc::kLimitExceeded, std::format("{} connections from the source of {} (its IPv4 address or IPv6 /64) are already authenticating", source_cap_, link->peer()), kWhere);
        }
    }
    if (pending_.size() >= total_cap_ &&
        !make_room(std::nullopt, make_error(errc::kLimitExceeded, std::format("closed to make room: it sent nothing while {} connections were waiting", total_cap_), kWhere))) {
        return fail(errc::kLimitExceeded, std::format("{} connections are already authenticating", pending_.size()), kWhere);
    }
    auto heard = std::make_shared<bool>(false);
    link = std::make_unique<watched_link>(std::move(link), heard);
    const ticket t = ++last_;
    pending_.emplace(t, entry{source, std::move(heard), clock::now() + first_byte_, std::move(close)});
    if (source) {
        ++per_source_[*source];
    }
    if (first_byte_.count() != 0 && !armed_) {
        arm_timer();
    }
    return t;
}

void admission::release(ticket t) noexcept {
    if (const auto it = pending_.find(t); it != pending_.end()) {
        (void)take(it); // its close function goes unused: the connection is the caller's
    }
}

bool admission::make_room(const std::optional<net::ip_address>& source, const error& why) {
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (!*it->second.heard && (!source || it->second.source == source)) {
            if (const close_fn close = take(it)) {
                close(why);
            }
            return true;
        }
    }
    return false;
}

admission::close_fn admission::take(std::map<ticket, entry>::iterator it) {
    if (it->second.source) {
        if (const auto count = per_source_.find(*it->second.source); count != per_source_.end() && --count->second == 0) {
            per_source_.erase(count);
        }
    }
    close_fn close = std::move(it->second.close);
    pending_.erase(it);
    return close;
}

void admission::arm_timer() {
    // Entries arrive in order and share one delay: the earliest deadline is the oldest silent one's.
    for (const auto& [t, e] : pending_) {
        if (!*e.heard) {
            const auto wait = std::chrono::ceil<std::chrono::milliseconds>(e.deadline - clock::now());
            armed_ = e.deadline;
            timer_.start(wait.count() > 0 ? wait : std::chrono::milliseconds{0}, [this] { on_timer(); });
            return;
        }
    }
    armed_.reset();
}

void admission::on_timer() {
    armed_.reset();
    const auto now = clock::now();
    std::vector<close_fn> late;
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (*it->second.heard) {
            ++it;
            continue;
        }
        if (it->second.deadline > now) {
            break;
        }
        late.push_back(take(it++));
    }
    arm_timer();
    const error why = make_error(errc::kTimeout, std::format("the peer sent nothing within {} ms", first_byte_.count()), kWhere);
    for (const close_fn& close : late) {
        if (close) {
            close(why);
        }
    }
}

} // namespace Rhp::session
