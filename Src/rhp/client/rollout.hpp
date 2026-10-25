#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/net/discovery.hpp>

namespace Rhp {

// How Rhp::fleet::rollout spreads a release over its members.
struct rollout_stage {
    double fraction = 1.0;                // of all members, cumulative (0.1 then 0.5 then 1.0)
    std::chrono::milliseconds observe{0}; // how long the stage's hosts are watched before they are confirmed
};

struct rollout_plan {
    // Members (service_record::name) that go first, as a stage of their own observed like the first stage.
    std::vector<std::string> canaries;
    std::vector<rollout_stage> stages{{0.1, std::chrono::seconds{30}}, {0.5, std::chrono::seconds{30}}, {1.0, std::chrono::milliseconds{0}}};
    std::chrono::milliseconds poll{500};                 // status checks while observing
    std::size_t max_failures = 0;                        // hosts that may fail (refuse, roll back, stop answering) before the rollout stops
    bool rollback_on_failure = true;                     // a stopped rollout deactivates the release on the hosts it applied it to
    std::function<void(std::string_view)> on_progress{}; // one line per step, on the calling thread
};

// One member's part in a rollout.
struct rollout_host {
    enum class state : std::uint8_t {
        kPending,    // its stage wasn't reached
        kConfirmed,  // runs the release, confirmed
        kAlready,    // ran it already
        kSkipped,    // not meant for it (another app, build or platform), or it runs a newer release in the channel
        kFailed,     // refused it (also: rolled back or quarantined there before), rolled it back, or stopped answering
        kRolledBack, // the rollout stopped and deactivated it there
    };
    net::service_record host;
    state status = state::kPending;
    std::optional<error> err{};
};

[[nodiscard]] constexpr std::string_view to_string(rollout_host::state s) noexcept {
    switch (s) {
    case rollout_host::state::kPending: return "pending";
    case rollout_host::state::kConfirmed: return "confirmed";
    case rollout_host::state::kAlready: return "already";
    case rollout_host::state::kSkipped: return "skipped";
    case rollout_host::state::kFailed: return "failed";
    case rollout_host::state::kRolledBack: return "rolled_back";
    }
    return "unknown";
}

struct rollout_report {
    bool completed = false; // every stage passed and at least one host runs the release
    std::size_t stages_done = 0;
    std::string channel;
    std::string release;             // hex id
    std::vector<rollout_host> hosts; // member order
    std::optional<error> err{};      // why it stopped (or couldn't start: a fraction outside [0, 1], an unknown canary)
};

} // namespace Rhp
