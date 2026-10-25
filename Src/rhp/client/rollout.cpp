// Rhp::fleet::rollout: a release spread over a fleet in stages, each watched before the next.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/client/detail/fleet_engine.hpp>
#include <rhp/client/rollout.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::fleet_detail {

namespace {

using clock = std::chrono::steady_clock;
using host_state = rollout_host::state;

// What the rollout needs of the envelope (the hosts check everything else): its channel and id.
struct peeked {
    std::string channel;
    security::digest256 id{};
};

result<peeked> peek(std::span<const std::byte> envelope) {
    auto v = wire::msgpack::decode(utils::bytes_view{envelope.data(), envelope.size()});
    const value* tag = v ? v->find("rhp") : nullptr;
    const value* body = v ? v->find("body") : nullptr;
    if (tag == nullptr || tag->get_if<std::string>() == nullptr || *tag->get_if<std::string>() != "release-envelope" || body == nullptr ||
        body->get_if<value::bytes>() == nullptr) {
        return fail(errc::kProtocol, "not a release envelope", "fleet.rollout");
    }
    const auto& bytes = *body->get_if<value::bytes>();
    auto m = wire::msgpack::decode(utils::bytes_view{bytes.data(), bytes.size()});
    const value* channel = m ? m->find("channel") : nullptr;
    if (channel == nullptr || channel->get_if<std::string>() == nullptr) {
        return fail(errc::kProtocol, "the release body names no channel", "fleet.rollout");
    }
    return peeked{*channel->get_if<std::string>(), security::blake2b_256(bytes)};
}

bool same_id(const value::bytes& a, const security::digest256& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

// Does this host run the release (as candidate or active) in the channel?
bool runs(const wire::release_status_reply& status, std::string_view channel, const security::digest256& id) {
    for (const auto& c : status.channels) {
        if (c.channel != channel) {
            continue;
        }
        return (c.candidate && same_id(c.candidate->id, id)) || (c.active && same_id(c.active->id, id) && c.running != "empty");
    }
    return false;
}

class rollout_run {
public:
    rollout_run(engine& e, std::span<const std::byte> envelope, const rollout_plan& plan) : e_(e), envelope_(envelope.begin(), envelope.end()), plan_(plan) {}

    rollout_report run() {
        auto p = peek(envelope_);
        if (!p) {
            report_.err = p.error();
            return report_;
        }
        peek_ = std::move(*p);
        report_.channel = peek_.channel;
        report_.release = security::to_hex(peek_.id);
        for (auto& record : records(e_)) {
            report_.hosts.push_back(rollout_host{std::move(record), host_state::kPending, std::nullopt});
        }
        if (report_.hosts.empty()) {
            report_.err = make_error(errc::kNotFound, "the fleet has no members", "fleet.rollout");
            return report_;
        }
        const std::vector<planned_stage> stages = plan_stages();
        for (std::size_t index = 0; index < stages.size(); ++index) {
            progress(std::format("stage {}: {} host(s)", index + 1, stages[index].hosts.size()));
            if (!run_stage(stages[index].hosts, stages[index].observe)) {
                stop();
                return report_;
            }
            ++report_.stages_done;
        }
        report_.completed = true;
        progress("rollout complete");
        return report_;
    }

private:
    struct planned_stage {
        std::vector<std::size_t> hosts; // member indices
        std::chrono::milliseconds observe{0};
    };

    // Canaries first (observed like the first stage), then the rest in an order fixed by the
    // release: the same hosts go first each time this release is rolled out, others for another.
    std::vector<planned_stage> plan_stages() const {
        const std::size_t n = report_.hosts.size();
        std::vector<std::size_t> canaries;
        std::vector<std::size_t> rest;
        for (std::size_t i = 0; i < n; ++i) {
            const bool canary = std::ranges::find(plan_.canaries, report_.hosts[i].host.name) != plan_.canaries.end();
            (canary ? canaries : rest).push_back(i);
        }
        const auto key = [&](std::size_t i) {
            const auto& h = report_.hosts[i].host;
            return security::blake2b_256(std::format("{}|{}|{}|{}", report_.release, h.name, h.address, h.port));
        };
        std::ranges::sort(rest, [&](std::size_t a, std::size_t b) { return key(a) < key(b); });
        const auto first_observe = plan_.stages.empty() ? std::chrono::milliseconds{0} : plan_.stages.front().observe;
        std::vector<planned_stage> out;
        if (!canaries.empty()) {
            out.push_back(planned_stage{std::move(canaries), first_observe});
        }
        std::size_t taken = 0;
        for (const rollout_stage& s : plan_.stages) {
            const auto wanted = std::ceil(std::clamp(s.fraction, 0.0, 1.0) * static_cast<double>(rest.size()));
            const auto target = std::min(rest.size(), static_cast<std::size_t>(wanted));
            if (target > taken) {
                out.push_back(planned_stage{{rest.begin() + static_cast<std::ptrdiff_t>(taken), rest.begin() + static_cast<std::ptrdiff_t>(target)}, s.observe});
                taken = target;
            }
        }
        if (taken < rest.size()) { // stages that don't reach 1.0: the rest last, unobserved
            out.push_back(planned_stage{{rest.begin() + static_cast<std::ptrdiff_t>(taken), rest.end()}, std::chrono::milliseconds{0}});
        }
        return out;
    }

    bool run_stage(const std::vector<std::size_t>& stage, std::chrono::milliseconds observe) {
        // Apply, health-watched: a host that sees the release fail rolls it back by itself.
        const value body = Rhp::to_value(wire::release_apply_request{value::bytes(envelope_.begin(), envelope_.end()), "health"});
        std::vector<std::size_t> applied;
        const auto outcomes = send(e_, wire::op::kReleaseApply, body, stage);
        for (std::size_t k = 0; k < outcomes.size(); ++k) {
            const outcome& o = outcomes[k];
            rollout_host& h = report_.hosts[stage[k]];
            if (o.body) {
                auto reply = Rhp::from_value<wire::release_apply_reply>(*o.body);
                h.status = reply && reply->already ? host_state::kAlready : host_state::kPending;
                applied.push_back(stage[k]);
            } else if (o.body.error().code == errc::kOutOfScope || o.body.error().code == errc::kSuperseded) {
                h.status = host_state::kSkipped;
                h.err = o.body.error();
            } else {
                fail_host(h, o.body.error());
            }
        }
        if (over_budget()) {
            return false;
        }
        // Watch.
        const auto until = clock::now() + observe;
        while (clock::now() < until && !applied.empty()) {
            wait(std::min(plan_.poll, std::chrono::ceil<std::chrono::milliseconds>(until - clock::now())));
            check(applied);
            if (over_budget()) {
                return false;
            }
        }
        // Confirm what is still a candidate (a host that confirmed itself answers kNotFound).
        const value confirm = Rhp::to_value(wire::release_channel_request{peek_.channel, false});
        const auto confirmed = send(e_, wire::op::kReleaseConfirm, confirm, applied);
        for (std::size_t k = 0; k < applied.size(); ++k) {
            rollout_host& h = report_.hosts[applied[k]];
            if (h.status == host_state::kFailed) {
                continue;
            }
            if (!confirmed[k].body && confirmed[k].body.error().code != errc::kNotFound) {
                fail_host(h, confirmed[k].body.error());
                continue;
            }
            if (h.status != host_state::kAlready) {
                h.status = host_state::kConfirmed;
            }
        }
        check(applied); // one last look: confirmed means it runs
        return !over_budget();
    }

    // Marks hosts that stopped running the release (rolled back, or not answering) failed.
    void check(const std::vector<std::size_t>& hosts) {
        std::vector<std::size_t> live;
        for (const std::size_t i : hosts) {
            if (report_.hosts[i].status != host_state::kFailed) {
                live.push_back(i);
            }
        }
        const auto statuses = send(e_, wire::op::kReleaseStatus, value{}, live);
        for (std::size_t k = 0; k < live.size(); ++k) {
            rollout_host& h = report_.hosts[live[k]];
            if (!statuses[k].body) {
                fail_host(h, statuses[k].body.error());
                continue;
            }
            auto status = Rhp::from_value<wire::release_status_reply>(*statuses[k].body);
            if (!status || !runs(*status, peek_.channel, peek_.id)) {
                fail_host(h, make_error(errc::kRuntime, "the host no longer runs the release (rolled back)", "fleet.rollout"));
            }
        }
    }

    // Deactivates the release wherever it still runs.
    void stop() {
        progress(std::format("rollout stopped after {} stage(s): {} host(s) failed", report_.stages_done, failures_));
        if (!report_.err) {
            report_.err = make_error(errc::kRuntime, std::format("{} host(s) failed (at most {} allowed)", failures_, plan_.max_failures), "fleet.rollout");
        }
        if (!plan_.rollback_on_failure) {
            return;
        }
        std::vector<std::size_t> touched;
        for (std::size_t i = 0; i < report_.hosts.size(); ++i) {
            const auto s = report_.hosts[i].status;
            if (s == host_state::kConfirmed || s == host_state::kPending || s == host_state::kFailed) {
                touched.push_back(i);
            }
        }
        const auto statuses = send(e_, wire::op::kReleaseStatus, value{}, touched);
        std::vector<std::size_t> running;
        for (std::size_t k = 0; k < touched.size(); ++k) {
            auto status = statuses[k].body ? Rhp::from_value<wire::release_status_reply>(*statuses[k].body) : result<wire::release_status_reply>{std::unexpected{statuses[k].body.error()}};
            if (status && runs(*status, peek_.channel, peek_.id)) {
                running.push_back(touched[k]);
            }
        }
        const value body = Rhp::to_value(wire::release_channel_request{peek_.channel, false});
        const auto out = send(e_, wire::op::kReleaseDeactivate, body, running);
        for (std::size_t k = 0; k < running.size(); ++k) {
            rollout_host& h = report_.hosts[running[k]];
            if (out[k].body) {
                h.status = host_state::kRolledBack;
            } else {
                h.err = out[k].body.error();
            }
        }
    }

    void fail_host(rollout_host& h, error err) {
        if (h.status != host_state::kFailed) {
            ++failures_;
            progress(std::format("{}: {}", h.host.name, err.message));
        }
        h.status = host_state::kFailed;
        h.err = std::move(err);
    }

    [[nodiscard]] bool over_budget() const noexcept { return failures_ > plan_.max_failures; }

    void wait(std::chrono::milliseconds d) {
        const auto until = clock::now() + d;
        while (clock::now() < until) {
            poll(e_);
            std::this_thread::sleep_for(std::min(std::chrono::milliseconds{10}, std::chrono::ceil<std::chrono::milliseconds>(until - clock::now())));
        }
    }

    void progress(std::string_view line) const {
        if (plan_.on_progress) {
            plan_.on_progress(line);
        }
    }

    engine& e_;
    std::vector<std::byte> envelope_;
    const rollout_plan& plan_;
    peeked peek_;
    rollout_report report_;
    std::size_t failures_ = 0;
};

} // namespace

rollout_report rollout(engine& e, std::span<const std::byte> envelope, const rollout_plan& plan) {
    return rollout_run{e, envelope, plan}.run();
}

} // namespace Rhp::fleet_detail
