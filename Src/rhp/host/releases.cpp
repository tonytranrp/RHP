#include <algorithm>
#include <chrono>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/host/detail/releases.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

namespace {

value::bytes id_bytes(const release::release_id& id) {
    return value::bytes(id.begin(), id.end());
}

std::optional<wire::release_info_message> info_message(const std::optional<release::release_info>& info) {
    if (!info) {
        return std::nullopt;
    }
    return wire::release_info_message{id_bytes(info->id), info->seq, info->label, info->signers};
}

std::string_view kind_name(release::release_event::kind k) noexcept {
    switch (k) {
    case release::release_event::kind::kApplied: return "applied";
    case release::release_event::kind::kConfirmed: return "confirmed";
    case release::release_event::kind::kRolledBack: return "rolled_back";
    case release::release_event::kind::kRefused: return "refused";
    case release::release_event::kind::kRevocations: return "revocations";
    }
    return "unknown";
}

// The wire form of a manager's status.
wire::release_status_reply to_message(const release::manager& m) {
    wire::release_status_reply out;
    out.app = m.options().app;
    out.build = m.options().build;
    out.platform = m.options().platform;
    out.revocation_seq = m.revocation_seq();
    for (const release::channel_status& s : m.status()) {
        wire::channel_status_message c;
        c.channel = s.channel;
        c.running = std::string{release::to_string(s.running)};
        c.active = info_message(s.active);
        c.candidate = info_message(s.candidate);
        c.previous = s.previous ? id_bytes(*s.previous) : value::bytes{};
        c.floor = s.floor;
        c.held = s.held;
        c.attempts = s.attempts;
        c.confirm = std::string{release::to_string(s.confirm)};
        c.handler_failures = s.handler_failures;
        c.modules = s.modules;
        out.channels.push_back(std::move(c));
    }
    return out;
}

result<value> handle(release::manager& m, wire::op code, const value& body) {
    switch (code) {
    case wire::op::kReleaseApply: {
        auto req = Rhp::from_value<wire::release_apply_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        const auto mode = release::parse_confirm_mode(req->confirm);
        if (!mode) {
            return fail(errc::kInvalidArgument, std::format("confirm is now, health or manual, not '{}'", req->confirm), "release_apply");
        }
        auto r = m.apply(req->envelope, *mode);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        wire::release_apply_reply out{r->channel, id_bytes(r->id), r->seq, std::string{release::to_string(r->running)}, r->already,
                                      r->replaced ? id_bytes(*r->replaced) : value::bytes{}, r->signers};
        return Rhp::to_value(out);
    }
    case wire::op::kReleaseConfirm:
    case wire::op::kReleaseDeactivate: {
        auto req = Rhp::from_value<wire::release_channel_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        std::optional<release::release_id> expected;
        if (!req->release.empty()) {
            if (req->release.size() != release::release_id{}.size()) {
                return fail(errc::kInvalidArgument, "release is a 32-byte release id", "release_channel");
            }
            expected.emplace();
            std::ranges::copy(req->release, expected->begin());
        }
        auto r = code == wire::op::kReleaseConfirm ? m.confirm(req->channel, expected) : m.deactivate(req->channel, req->hold, expected);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{id_bytes(*r)};
    }
    case wire::op::kReleaseStatus: return Rhp::to_value(to_message(m));
    case wire::op::kRevoke: {
        auto req = Rhp::from_value<wire::revoke_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        auto r = m.revoke(req->envelope);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{*r};
    }
    default: return fail(errc::kProtocol, "not a release request", "host.releases");
    }
}

} // namespace

release_bridge bridge(release::manager& m) {
    release_bridge b;
    b.handle = [&m](wire::op code, const value& body) { return handle(m, code, body); };
    b.pump = [&m] { m.pump(); };
    b.harden = [&m](hardening level) { return m.harden(level); };
    b.on_event = [&m](std::function<void(event::release_changed)> publish) {
        return m.on_event([publish = std::move(publish)](const release::release_event& e) {
            event::release_changed out;
            out.time = std::chrono::system_clock::now();
            out.kind = std::string{kind_name(e.what)};
            out.channel = e.channel;
            out.release = e.release ? release::to_hex(*e.release) : std::string{};
            out.fallback = e.fallback ? release::to_hex(*e.fallback) : std::string{};
            out.seq = e.seq;
            out.reason = e.reason;
            out.outcome = e.err.value_or(error{});
            publish(std::move(out));
        });
    };
    return b;
}

} // namespace Rhp::host_detail
