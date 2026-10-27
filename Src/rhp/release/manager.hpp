#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::release {

// How an applied release becomes the channel's active one.
enum class confirm_mode : std::uint8_t {
    kNow,    // at once (the previous one is kept to fall back to)
    kHealth, // after health_window passes without a failure; a failure rolls it back
    kManual, // when confirm() is called; deactivate() rolls it back
};

[[nodiscard]] constexpr std::string_view to_string(confirm_mode m) noexcept {
    switch (m) {
    case confirm_mode::kNow: return "now";
    case confirm_mode::kHealth: return "health";
    case confirm_mode::kManual: return "manual";
    }
    return "unknown";
}

// "now" / "health" / "manual" (what to_string writes); nullopt for anything else.
[[nodiscard]] constexpr std::optional<confirm_mode> parse_confirm_mode(std::string_view text) noexcept {
    for (const confirm_mode m : {confirm_mode::kNow, confirm_mode::kHealth, confirm_mode::kManual}) {
        if (to_string(m) == text) {
            return m;
        }
    }
    return std::nullopt;
}

struct manager_options {
    std::string app;                                                               // compared with manifest::app
    std::string build;                                                             // compared with manifest::builds
    std::string platform{platform::to_string(platform::kOs)};                      // compared with manifest::platforms
    role max_role = role::kPatch;                                                  // releases asking to run as more are refused
    std::chrono::seconds clock_skew{300};                                          // allowance on not_before / not_after
    bool expire_running = true;                                                    // a running release past not_after is deactivated
    std::uint32_t max_boot_attempts = 2;                                           // restarts a candidate may run through unconfirmed before it is quarantined (above 1000: never)
    std::chrono::milliseconds health_window{60'000};                               // kHealth: confirmed after this long without a failure
    std::uint64_t max_seq_jump = std::uint64_t{1} << 32;                           // seq may grow by at most this much at once
    Rhp::limits limits{};                                                          // the channels' sandboxes (wall_ms 10 s when 0)
    std::function<std::chrono::system_clock::time_point()> wall_clock{};           // for validity windows; empty: system_clock::now
    script::clock_fn clock{};                                                      // script time and health windows; empty: steady_clock::now
    std::function<void(std::string_view channel, std::string_view line)> output{}; // print() of the channels' scripts
    // The compiled-chunk cache (bytecode.hpp): with a key, the Lua bytecode of every release a channel
    // runs is kept in the store next to its envelope, MAC'd under this key, and later loads (a restart,
    // a fallback) load it instead of parsing the sources. A host-local secret (16..64 bytes, e.g.
    // security::key::generate() kept in the OS keychain), never shared with clients nor kept where
    // the store's writers can read it: whoever holds it can make bytecode this host runs unchecked.
    // Empty (the default): nothing is cached, every load parses.
    security::key bytecode_key{};
};

// The compiled-chunk cache (manager_options::bytecode_key), as manager::bytecode_cache_stats reports it.
struct bytecode_stats {
    std::uint64_t loaded = 0;         // modules loaded from cached bytecode (their sources weren't parsed)
    std::uint64_t compiled = 0;       // modules compiled here for the cache (no entry yet, or one thrown away)
    std::uint64_t stored = 0;         // entries written
    std::uint64_t discarded = 0;      // entries thrown away, the sources parsed instead: a MAC that doesn't match (another key, an edit), truncated or malformed, another Lua build, another release's, bytecode Lua refused
    std::uint64_t store_failures = 0; // entries that couldn't be written (the release runs all the same)
    std::optional<error> last_discarded{}; // why the latest entry was thrown away
};

// A release a channel holds, as status reports it.
struct release_info {
    release_id id{};
    std::uint64_t seq = 0;
    std::string label;
    std::vector<std::string> signers;
};

enum class slot : std::uint8_t {
    kEmpty,     // nothing runs
    kActive,    // the active release runs
    kCandidate, // a candidate runs, waiting for its confirmation
};

[[nodiscard]] constexpr std::string_view to_string(slot s) noexcept {
    switch (s) {
    case slot::kEmpty: return "empty";
    case slot::kActive: return "active";
    case slot::kCandidate: return "candidate";
    }
    return "unknown";
}

struct channel_status {
    std::string channel;
    slot running = slot::kEmpty;
    std::optional<release_info> active;
    std::optional<release_info> candidate;
    std::optional<release_id> previous;
    std::uint64_t floor = 0;    // releases need a higher seq
    bool held = false;          // deactivated with hold: nothing runs until a new release is applied
    std::uint32_t attempts = 0; // restarts the candidate has run through
    confirm_mode confirm = confirm_mode::kNow;
    std::uint64_t handler_failures = 0; // while a health-watched candidate runs
    std::vector<std::string> modules;   // loaded right now
};

struct apply_result {
    std::string channel;
    release_id id{};
    std::uint64_t seq = 0;
    slot running = slot::kActive;         // kCandidate unless confirmed at once
    bool already = false;                 // that exact release was running: nothing changed
    std::optional<release_id> replaced{}; // what ran before
    std::vector<std::string> signers;
};

struct restore_report {
    std::vector<std::string> restored;                           // channels running again
    std::vector<std::pair<std::string, error>> failed;           // releases given up on (their channel runs its fallback, or nothing); "*": the stored revocation list or the state
    std::vector<std::pair<std::string, error>> deferred;         // channels that run nothing this time but keep their releases (an unreadable file, a lib installed after restore(), a clock outside the validity window, a load out of time or memory): tried again at the next restore
    std::vector<std::pair<std::string, release_id>> quarantined; // candidates given up on (too many restarts unconfirmed, or they failed to load)
};

// What a manager reports as it works (manager::on_event).
struct release_event {
    enum class kind : std::uint8_t {
        kApplied,     // a release started running (active or candidate)
        kConfirmed,   // a candidate became active
        kRolledBack,  // a candidate or an active release stopped; `fallback` runs instead (or nothing)
        kRefused,     // apply() refused a release (`err`)
        kRevocations, // a revocation list was applied
    };
    kind what = kind::kApplied;
    std::string channel;
    std::optional<release_id> release{};
    std::optional<release_id> fallback{};
    std::uint64_t seq = 0;
    std::string reason; // why it rolled back ("unhealthy: handler failures", "deactivated", "revoked", "expired")
    std::optional<error> err{};
};

namespace detail {
class manager_impl;
} // namespace detail

// Runs signed releases in channels: a channel is one sandbox the manager owns, running the modules
// of at most one release at a time. Releases arrive as envelopes (apply), are checked against the
// trust, the host's app / build / platform, their validity window and the channel's seq floor, are
// kept in the store, and swap in without a gap (modules reload in place; a failure leaves the old
// release running). The store keeps what runs, so restore() brings it back after a restart; a
// candidate that keeps failing to get confirmed is quarantined instead.
//
//   Rhp::release::manager releases{*Rhp::release::trust::from_file("rhp_release_signers.pub"),
//                                  {.app = "mygame", .build = "1.4.2"},
//                                  Rhp::release::directory_store{"save/releases"}};
//   releases.install<game_lib>();
//   releases.restore();
//   while (running) { releases.pump(); game::update(); }   // or host.serve(releases): host.pump() pumps it
//
// Revocation lists only add up: once a release, a key or a seq floor is revoked it stays revoked,
// whatever later lists say. The store's state is checksummed against torn and corrupted writes, not
// against someone who can write the store (they can lower floors; only signed releases ever run).
//
// A change (apply, confirm, deactivate) needs the last state saved: while a save keeps failing they
// fail too (pump() retries the save), so what runs never drifts from what a restart brings back.
// A revocation list takes effect even when it can't be saved.
//
// Single-threaded: use it from one thread (the pump thread), not from a channel's own scripts (that
// is refused) nor from a listener that throws. Don't move a manager a host serves. With
// RHP_ENABLE=0 it is inert: every operation reports kDisabled.
class manager {
public:
    explicit manager(trust keys, manager_options options = {}, any_store store = memory_store{});
    ~manager();
    manager(const manager&) = delete;
    manager& operator=(const manager&) = delete;
    manager(manager&&) noexcept;
    manager& operator=(manager&&) noexcept;

    // A lib every channel gets. Install before restore() / apply().
    template <script::installable L>
    result<void> install() {
        return install_lib(L::name, [](script::sandbox& box) { return box.install<L>(); });
    }

    // Brings back what the store says ran (once). apply / confirm / deactivate / revoke call it when it
    // hasn't run; until it succeeds (the store reads and its state checks out) they fail too, so a
    // store that can't be read is never overwritten.
    result<restore_report> restore();

    // Checks and runs a release envelope. A release with the seq of the running one and the same
    // id is `already`; otherwise seq must be above the channel's floor.
    result<apply_result> apply(std::span<const std::byte> envelope, confirm_mode mode = confirm_mode::kNow);

    // The running candidate becomes active; returns its id. With `expected`, kSuperseded unless that
    // is the candidate (a rollout confirms only what it applied).
    result<release_id> confirm(std::string_view channel, std::optional<release_id> expected = std::nullopt);

    // Stops what runs; returns its id. A candidate falls back to the active release (then the
    // previous), an active one to the previous; with `hold` the channel runs nothing until a new
    // release arrives. With `expected`, kSuperseded unless that release runs.
    result<release_id> deactivate(std::string_view channel, bool hold = false, std::optional<release_id> expected = std::nullopt);

    // Applies a signed revocation list newer than any applied before, signed by keys no list revoked:
    // revoked releases, releases at or below a revoked floor and releases signed only by revoked keys
    // stop (and are never fallen back to), floors rise. Returns how many channels changed.
    result<std::size_t> revoke(std::span<const std::byte> envelope);

    [[nodiscard]] std::vector<channel_status> status() const;
    [[nodiscard]] std::uint64_t revocation_seq() const noexcept;
    // The report of the restore that ran (explicitly, or by the first change), if one did.
    [[nodiscard]] const std::optional<restore_report>& last_restore() const noexcept;

    // Pumps every channel's sandbox, watches candidates' health and validity windows.
    void pump();

    // Calls fn for every release_event, on the pump thread, while the subscription lives (it may
    // outlive the manager).
    [[nodiscard]] Rhp::subscription on_event(std::function<void(const release_event&)> fn);

    // The channel's sandbox (nullptr when nothing runs there): for tests and inspection.
    [[nodiscard]] script::sandbox* sandbox(std::string_view channel) noexcept;

    [[nodiscard]] const manager_options& options() const noexcept;

    // What the compiled-chunk cache did so far (all zero without manager_options::bytecode_key).
    [[nodiscard]] bytecode_stats bytecode_cache_stats() const;

private:
    result<void> install_lib(std::string_view name, result<void> (*fn)(script::sandbox&));

    std::unique_ptr<detail::manager_impl> impl_;
};

} // namespace Rhp::release
