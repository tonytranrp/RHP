#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/listener_table.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/detail/compiled_cache.hpp>
#include <rhp/release/detail/state.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::release {

namespace detail {

namespace {

using steady = std::chrono::steady_clock;

constexpr std::string_view kStateKey = "state";
constexpr std::string_view kRevocationsKey = "revocations"; // the newest list (stores written before every list was kept)
constexpr std::string_view kRevocationsPrefix = "revocations/"; // every accepted list, by seq
constexpr std::uint32_t kDefaultWallMs = 10'000;

std::string release_key(const release_id& id) {
    return std::string{kReleasesPrefix} + to_hex(id);
}

std::string revocations_key(std::uint64_t seq) {
    return std::format("{}{:020}", kRevocationsPrefix, seq); // zero-padded: keys sort by seq
}

std::uint64_t unix_seconds(std::chrono::system_clock::time_point t) {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return s < 0 ? 0 : static_cast<std::uint64_t>(s);
}

// Where a refusal of a channel's release points: "release 'game.balance'".
std::string channel_where(std::string_view channel) {
    return std::format("release '{}'", channel);
}

error refused(errc code, std::string message, std::string_view channel) {
    return make_error(code, std::move(message), channel_where(channel));
}

// A save that failed, as the error of the change that needed it: its code, "<what>: <why>".
error save_failed(const error& why, std::string_view what, std::string where) {
    return make_error(why.code, std::format("{}: {}", what, why.message), std::move(where));
}

// A stored release a restore couldn't read or check may still run at the next one: the store
// couldn't be read, a lib it needs isn't installed yet, or the clock is off (before not_before, or
// past not_after: the clock may be the one that is wrong). Anything else gives it up.
bool kept_after_read(const error& e) {
    switch (e.code) {
    case errc::kRuntime: // the store's I/O
    case errc::kTimeout:
    case errc::kTransport:
    case errc::kCancelled:
    case errc::kNotFound: // a lib
    case errc::kExpired: return true;
    default: return false;
    }
}

// A stored release whose modules failed to load at restore may load the next time when it ran out
// of time or memory (a slow first start); a script error gives it up.
bool kept_after_load(const error& e) {
    return e.code == errc::kTimeout || e.code == errc::kBudgetExceeded || e.code == errc::kMemoryExceeded;
}

// The manager's event listeners: a subscription may outlive the manager.
class release_listeners final : public subscribable {
public:
    std::uint64_t add(std::function<void(const release_event&)> fn) { return table_.add(0, std::move(fn)); }
    void unsubscribe(std::uint64_t id) noexcept override { (void)table_.remove(id); }
    void dispatch(const release_event& e) const {
        table_.dispatch([](int) { return true; }, e);
    }

private:
    core::listener_table<int, std::function<void(const release_event&)>> table_;
};

} // namespace

// A release that passed the checks, with who signed it.
struct checked_release {
    release r;
    std::vector<std::string> signers;
};

struct channel_runtime {
    channel_state state;
    std::unique_ptr<script::sandbox> box;
    role box_role = role::kPatch;
    std::optional<checked_release> running; // what the sandbox runs (the active release or the candidate)
    std::vector<std::pair<std::string, module_id>> modules;
    std::optional<release_info> active_info;
    // Health of a watched candidate.
    steady::time_point watch_started{};
    std::uint64_t handler_failures = 0;
    std::string unhealthy;
    std::vector<Rhp::subscription> watches;

    // The sandbox runs the candidate (not the active release).
    [[nodiscard]] bool runs_candidate() const noexcept { return state.candidate && running && running->r.id == *state.candidate; }
};

class manager_impl {
public:
    manager_impl(trust keys, manager_options options, any_store store)
        : keys_(std::move(keys)), options_(std::move(options)), store_(std::move(store)) {
        if (options_.limits.wall_ms == 0) {
            options_.limits.wall_ms = kDefaultWallMs;
        }
    }

    // The sandboxes go first, while channels_ is whole: their callbacks (on_handler_error, the health
    // watches) look their channel up in it.
    ~manager_impl() {
        for (auto& [name, c] : channels_) {
            c.watches.clear();
            c.box.reset();
        }
    }

    manager_impl(const manager_impl&) = delete;
    manager_impl& operator=(const manager_impl&) = delete;

    result<void> install_lib(std::string_view name, result<void> (*fn)(script::sandbox&)) {
        if (has_lib(name)) {
            return fail(errc::kAlreadyLoaded, std::format("lib '{}' is already installed", name), "release.manager");
        }
        libs_.emplace_back(std::string{name}, fn);
        for (auto& [channel, c] : channels_) { // channels running now get it too
            if (c.box) {
                (void)fn(*c.box);
            }
        }
        return {};
    }

    Rhp::subscription on_event(std::function<void(const release_event&)> fn) {
        const std::uint64_t id = listeners_->add(std::move(fn));
        return Rhp::subscription{listeners_, id};
    }

    [[nodiscard]] const manager_options& options() const noexcept { return options_; }
    [[nodiscard]] std::uint64_t revocation_seq() const noexcept { return revoked_.seq; }
    [[nodiscard]] const bytecode_stats& bytecode_cache_stats() const noexcept { return cache_.bytecode_cache_stats(); }

    script::sandbox* sandbox(std::string_view channel) noexcept {
        const auto it = channels_.find(channel);
        return it != channels_.end() ? it->second.box.get() : nullptr;
    }

    // ---- restore ---------------------------------------------------------------------------------

    // Nothing changes until the state is read: a store that can't be read (or holds a corrupt state)
    // fails here, and every later change fails too (restore() is tried again each time) instead of
    // overwriting what the store holds.
    result<restore_report> restore() {
        if (restored_) {
            return fail(errc::kAlreadyLoaded, "restore() runs once, before the first apply()", "release.manager");
        }
        auto bytes = store_.read(kStateKey);
        std::optional<decoded_state> state;
        if (bytes) {
            auto decoded = decode_state(*bytes);
            if (!decoded) {
                return std::unexpected{std::move(decoded).error()};
            }
            state = std::move(*decoded);
        } else if (bytes.error().code != errc::kNotFound) {
            return std::unexpected{std::move(bytes).error()};
        }
        restore_report report;
        // Every revocation list kept: they only ever withdraw trust, so what they say counts even if
        // a signature no longer verifies (its signer rotated out). One that can't be read fails the
        // restore, like the state.
        revoked_set lists;
        if (auto read = read_lists(lists, report); !read) {
            return std::unexpected{std::move(read).error()};
        }
        restored_ = true;
        if (state) {
            revoked_ = std::move(state->revoked);
        }
        revoked_.merge(lists);
        // Every channel is known before any of them runs: a restore that persists part way (a
        // candidate's boot attempt) never forgets the others.
        if (state) {
            for (channel_state& s : state->channels) {
                channel_runtime& c = channels_[s.name];
                c.state = std::move(s);
            }
        }
        for (const seq_floor& f : revoked_.floors) {
            raise_floor(f);
        }
        for (auto& [name, c] : channels_) {
            restore_channel(c, report);
        }
        if (auto saved = persist(); !saved) {
            report.failed.emplace_back("*", std::move(saved).error());
        }
        collect_garbage();
        last_restore_ = report;
        return report;
    }

    [[nodiscard]] const std::optional<restore_report>& last_restore() const noexcept { return last_restore_; }

    // ---- apply -------------------------------------------------------------------------------------

    result<apply_result> apply(std::span<const std::byte> envelope, confirm_mode mode) {
        if (auto ready = ready_to_change(); !ready) {
            return refuse("", std::move(ready).error());
        }
        auto decoded = decode_release(envelope);
        if (!decoded) {
            return refuse("", std::move(decoded).error());
        }
        release& r = *decoded;
        const std::string channel = r.body.channel;
        if (!r.revocations.empty()) {
            if (auto rev = take_revocations(r.revocations); !rev && rev.error().code != errc::kSuperseded) {
                return refuse(channel, std::move(rev).error());
            }
        }
        auto checked = check(std::move(r));
        if (!checked) {
            return refuse(channel, std::move(checked).error());
        }
        const release_id id = checked->r.id;
        const std::uint64_t seq = checked->r.body.seq;
        channel_runtime* existing = find(channel);
        if (existing != nullptr && existing->running && existing->running->r.id == id) {
            apply_result same{channel, id, seq, current_slot(*existing), true, std::nullopt, checked->signers};
            return same;
        }
        if (existing != nullptr && std::ranges::find(existing->state.quarantined, id) != existing->state.quarantined.end()) {
            return refuse(channel, refused(errc::kRevoked, "this release was quarantined on this host (it never got confirmed across restarts)", channel));
        }
        const std::uint64_t floor = existing != nullptr ? existing->state.floor : 0;
        if (seq <= floor) {
            return refuse(channel, refused(errc::kSuperseded, std::format("seq {} is not above the channel's floor {}", seq, floor), channel));
        }
        if (floor != 0 && seq - floor > options_.max_seq_jump) {
            return refuse(channel, refused(errc::kOutOfRange, std::format("seq {} jumps more than {} past {}", seq, options_.max_seq_jump, floor), channel));
        }
        // Keep the envelope first: the state never names a release the store doesn't hold.
        auto bytes = encode_release(checked->r);
        if (!bytes) {
            return refuse(channel, std::move(bytes).error());
        }
        if (auto kept = store_.write(release_key(id), *bytes); !kept) {
            return refuse(channel, std::move(kept).error());
        }
        const bool created = existing == nullptr;
        channel_runtime& c = created ? channels_[channel] : *existing;
        c.state.name = channel;
        const channel_state before = c.state;
        const std::optional<checked_release> before_running = c.running;
        const std::optional<release_info> before_info = c.active_info;
        const std::optional<release_id> replaced = c.running ? std::optional<release_id>{c.running->r.id} : std::nullopt;
        if (auto swapped = swap_in(c, *checked); !swapped) {
            forget_if_empty(channel, created);
            collect_garbage();
            return refuse(channel, std::move(swapped).error());
        }
        c.state.floor = seq;
        c.state.held = false;
        c.state.attempts = 0;
        if (mode == confirm_mode::kNow) {
            promote_to_active(c, id);
            c.state.candidate.reset();
            c.watches.clear();
        } else {
            c.state.candidate = id;
            start_watch(c);
        }
        c.state.confirm = mode;
        if (auto saved = persist(); !saved) {
            // Not saved: put back what ran, so this process runs what a restart would bring back.
            c.watches.clear();
            c.state = before;
            put_back(c, before_running, before_info);
            forget_if_empty(channel, created);
            dirty_state_ = false; // the store still holds `before`
            collect_garbage();
            return refuse(channel, save_failed(saved.error(), "the release state couldn't be saved", channel_where(channel)));
        }
        collect_garbage();
        apply_result out{channel, id, seq, current_slot(c), false, replaced, c.running->signers};
        emit(release_event{release_event::kind::kApplied, channel, id, std::nullopt, seq, {}, std::nullopt});
        return out;
    }

    // ---- confirm / deactivate ---------------------------------------------------------------------

    result<release_id> confirm(std::string_view channel, const std::optional<release_id>& expected) {
        if (auto ready = ready_to_change(); !ready) {
            return std::unexpected{std::move(ready).error()};
        }
        channel_runtime* c = find(channel);
        if (c == nullptr || !c->runs_candidate()) {
            return fail(errc::kNotFound, std::format("channel '{}' runs no candidate", channel), "release.manager");
        }
        const release_id id = *c->state.candidate;
        if (expected && *expected != id) {
            return fail(errc::kSuperseded, std::format("channel '{}' runs candidate {}, not {}", channel, short_id(id), short_id(*expected)), "release.manager");
        }
        const channel_state before = c->state;
        const std::optional<release_info> before_info = c->active_info;
        promote_to_active(*c, id);
        c->state.candidate.reset();
        c->state.attempts = 0;
        c->state.confirm = confirm_mode::kNow;
        if (auto saved = persist(); !saved) {
            c->state = before; // still the candidate, still watched
            c->active_info = before_info;
            dirty_state_ = false;
            return std::unexpected{save_failed(saved.error(), "the release state couldn't be saved", "release.manager")};
        }
        c->watches.clear();
        c->unhealthy.clear();
        collect_garbage();
        emit(release_event{release_event::kind::kConfirmed, std::string{channel}, id, std::nullopt, c->running->r.body.seq, {}, std::nullopt});
        return id;
    }

    result<release_id> deactivate(std::string_view channel, bool hold, const std::optional<release_id>& expected) {
        if (auto ready = ready_to_change(); !ready) {
            return std::unexpected{std::move(ready).error()};
        }
        channel_runtime* c = find(channel);
        if (c == nullptr || !c->running) {
            return fail(errc::kNotFound, std::format("nothing runs in channel '{}'", channel), "release.manager");
        }
        const release_id stopped = c->running->r.id;
        if (expected && *expected != stopped) {
            return fail(errc::kSuperseded, std::format("channel '{}' runs {}, not {}", channel, short_id(stopped), short_id(*expected)), "release.manager");
        }
        roll_back(*c, hold ? "deactivated (held)" : "deactivated", hold);
        if (auto saved = persist(); !saved) {
            // It stopped; a restart would bring it back until the state is saved (pump() retries).
            return std::unexpected{save_failed(saved.error(), "deactivated, but the release state couldn't be saved", "release.manager")};
        }
        collect_garbage();
        return stopped;
    }

    // ---- revocations ---------------------------------------------------------------------------------

    result<std::size_t> revoke(std::span<const std::byte> envelope) {
        if (pumping_) {
            return std::unexpected{from_a_script()};
        }
        if (auto ready = ensure_restored(); !ready) {
            return std::unexpected{std::move(ready).error()};
        }
        auto changed = take_revocations(envelope);
        if (changed) {
            collect_garbage();
        }
        return changed;
    }

    // ---- status / pump -------------------------------------------------------------------------------

    [[nodiscard]] std::vector<channel_status> status() const {
        std::vector<channel_status> out;
        for (const auto& [name, c] : channels_) {
            channel_status s;
            s.channel = name;
            s.running = current_slot(c);
            s.active = c.active_info;
            if (c.runs_candidate()) {
                s.candidate = info_of(*c.running);
            }
            s.previous = c.state.previous;
            s.floor = c.state.floor;
            s.held = c.state.held;
            s.attempts = c.state.attempts;
            s.confirm = c.state.confirm;
            s.handler_failures = c.handler_failures;
            for (const auto& [mod, id] : c.modules) {
                s.modules.push_back(mod);
            }
            out.push_back(std::move(s));
        }
        return out;
    }

    void pump() {
        const auto now = steady_now();
        const std::uint64_t wall = unix_seconds(wall_now());
        const std::uint64_t skew = skew_seconds();
        for (auto& [name, c] : channels_) {
            if (c.box) {
                pumping_ = true; // a channel's script calling back into the manager is refused
                const utils::scope_guard pumped{[this]() noexcept { pumping_ = false; }};
                c.box->pump();
            }
            if (!c.running) {
                continue;
            }
            const manifest& m = c.running->r.body;
            if (options_.expire_running && m.not_after != 0 && wall > m.not_after + skew) {
                roll_back(c, "expired", false);
                (void)persist();
                continue;
            }
            if (!watched(c)) {
                continue;
            }
            if (c.unhealthy.empty() && c.handler_failures > m.health.max_handler_failures) {
                c.unhealthy = std::format("unhealthy: {} handler failures", c.handler_failures);
            }
            if (c.unhealthy.empty()) {
                for (const auto& [mod, id] : c.modules) {
                    if (const auto info = c.box->status(id); info && info->state == script::module_state::kFaulted) {
                        c.unhealthy = std::format("unhealthy: module '{}' faulted", mod);
                        break;
                    }
                }
            }
            if (!c.unhealthy.empty()) {
                roll_back(c, c.unhealthy, false);
                (void)persist();
            } else if (now - c.watch_started >= options_.health_window) {
                (void)confirm(name, std::nullopt);
            }
        }
        if (dirty_state_ && now >= retry_at_) { // an earlier save failed: try again, at most once a second
            if (!persist()) {
                retry_at_ = now + std::chrono::seconds{1};
            }
        }
        if (dirty_gc_) {
            collect_garbage();
        }
    }

private:
    static error from_a_script() {
        return make_error(errc::kInvalidArgument, "the release manager can't be called from a channel's script", "release.manager");
    }

    // Before a change: the store is restored and the last state saved (a failed save is tried once
    // more): nothing new is stacked on a state the store doesn't hold.
    result<void> ready_to_change() {
        if (pumping_) {
            return std::unexpected{from_a_script()};
        }
        if (auto ready = ensure_restored(); !ready) {
            return ready;
        }
        if (dirty_state_) {
            if (auto saved = persist(); !saved) {
                return fail(saved.error().code, std::format("the release state couldn't be saved ({}): nothing changes until it can", saved.error().message),
                            "release.manager");
            }
        }
        return {};
    }

    // Every revocation list the store keeps, merged into `out` (unverified: they only withdraw trust).
    result<void> read_lists(revoked_set& out, restore_report& report) {
        auto keys = store_.keys();
        if (!keys) {
            return std::unexpected{std::move(keys).error()};
        }
        for (const std::string& key : *keys) {
            if (key != kRevocationsKey && !key.starts_with(kRevocationsPrefix)) {
                continue;
            }
            auto bytes = store_.read(key);
            if (!bytes) {
                if (bytes.error().code == errc::kNotFound) {
                    continue;
                }
                return std::unexpected{std::move(bytes).error()};
            }
            if (auto list = decode_revocations(*bytes)) {
                out.merge(list->body);
            } else {
                report.failed.emplace_back("*", std::move(list).error());
            }
        }
        return {};
    }

    result<void> ensure_restored() {
        if (restored_) {
            return {};
        }
        auto r = restore();
        if (!r) {
            return fail(r.error().code, std::format("the release store couldn't be restored: {}", r.error().message), "release.manager");
        }
        return {};
    }

    // ---- checks ------------------------------------------------------------------------------------

    result<checked_release> check(release r) const {
        const std::string_view channel = r.body.channel;
        if (revoked_.revokes(r.id)) {
            return std::unexpected{refused(errc::kRevoked, "this release is revoked", channel)};
        }
        if (const std::uint64_t floor = revoked_.floor_of(channel); r.body.seq <= floor) {
            return std::unexpected{refused(errc::kRevoked, std::format("seq {} is at or below the revoked floor {}", r.body.seq, floor), channel)};
        }
        auto signers = keys_.verify(r, revoked_.keys);
        if (!signers) {
            return std::unexpected{std::move(signers).error()};
        }
        const manifest& m = r.body;
        if (!m.app.empty() && m.app != options_.app) {
            return std::unexpected{refused(errc::kOutOfScope, std::format("made for app '{}', this is '{}'", m.app, options_.app), channel)};
        }
        if (!m.builds.empty() && std::ranges::find(m.builds, options_.build) == m.builds.end()) {
            return std::unexpected{refused(errc::kOutOfScope, std::format("not made for build '{}'", options_.build), channel)};
        }
        if (!m.platforms.empty() && std::ranges::find(m.platforms, options_.platform) == m.platforms.end()) {
            return std::unexpected{refused(errc::kOutOfScope, std::format("not made for platform '{}'", options_.platform), channel)};
        }
        const std::uint64_t now = unix_seconds(wall_now());
        const std::uint64_t skew = skew_seconds();
        if (m.not_before != 0 && now + skew < m.not_before) {
            return std::unexpected{refused(errc::kExpired, "not valid yet (not_before is in the future)", channel)};
        }
        if (m.not_after != 0 && now > m.not_after + skew) {
            return std::unexpected{refused(errc::kExpired, "no longer valid (not_after has passed)", channel)};
        }
        if (!allows(options_.max_role, m.run_as)) {
            return std::unexpected{refused(errc::kForbidden, std::format("asks to run as {}, this host allows at most {}", m.run_as, options_.max_role), channel)};
        }
        for (const std::string& lib : m.libs) {
            if (!has_lib(lib)) {
                return std::unexpected{refused(errc::kNotFound, std::format("needs lib '{}', which this host doesn't have", lib), channel)};
            }
        }
        return checked_release{std::move(r), std::move(*signers)};
    }

    // ---- swapping ------------------------------------------------------------------------------------

    std::unique_ptr<script::sandbox> make_box(const std::string& channel, role run_as) {
        script::sandbox_options o;
        o.caller_role = run_as;
        o.limits = options_.limits;
        o.clock = options_.clock;
        o.identity = std::format("release:{}", channel);
        if (options_.output) {
            o.output = [out = options_.output, channel](std::string_view line) { out(channel, line); };
        }
        o.on_handler_error = [this, channel](const script::handler_failure&) {
            if (channel_runtime* c = find(channel); c != nullptr && watched(*c)) {
                ++c->handler_failures;
            }
        };
        auto box = std::make_unique<script::sandbox>(std::move(o));
        for (const auto& [name, fn] : libs_) {
            (void)fn(*box);
        }
        return box;
    }

    // Loads `next`'s modules into the channel. The old release keeps running if anything fails; if
    // it can't be put back either, the channel runs nothing (never a mix of the two).
    result<void> swap_in(channel_runtime& c, const checked_release& next) {
        const manifest& m = next.r.body;
        const bool fresh = !c.box || c.box_role != m.run_as;
        std::unique_ptr<script::sandbox> made = fresh ? make_box(m.channel, m.run_as) : nullptr;
        script::sandbox& box = fresh ? *made : *c.box;
        std::vector<std::pair<std::string, module_id>> modules;
        struct undo_step {
            module_id mod;
            bool reloaded; // else: loaded fresh
        };
        std::vector<undo_step> undo;
        // Undoes what this swap did; false if a step failed (the sandbox runs a mix).
        const auto compensate = [&] {
            bool clean = true;
            for (auto it = undo.rbegin(); it != undo.rend(); ++it) {
                if (it->reloaded) {
                    const auto back = box.rollback(it->mod, 1);
                    clean = clean && back && *back != revision_id{};
                } else {
                    clean = box.unload(it->mod, script::force).has_value() && clean;
                }
            }
            return clean;
        };
        const auto failed = [&](error err) -> result<void> {
            if (!compensate() && !fresh) {
                tear_down(c);
                err.message += " (the old release couldn't be put back: the channel runs nothing)";
            }
            return std::unexpected{std::move(err)};
        };
        chunk_set chunks = cache_.cached_chunks(next.r);
        for (std::size_t i = 0; i < m.modules.size(); ++i) {
            const std::string& name = m.modules[i].name;
            const auto existing = std::ranges::find(c.modules, name, &std::pair<std::string, module_id>::first);
            if (!fresh && existing != c.modules.end()) {
                const bool same = c.running && i < c.running->r.body.modules.size() && c.running->r.body.modules[i].name == name &&
                                  c.running->r.body.modules[i].hash == m.modules[i].hash;
                if (!same) {
                    auto rev = cache_.reload_module(box, existing->second, next.r, i, chunks);
                    if (!rev || *rev == revision_id{}) {
                        if (rev) { // suspended in its top level (or deferred): not a release's module
                            undo.push_back(undo_step{existing->second, true});
                            return failed(refused(errc::kRuntime, std::format("module '{}' suspended while loading", name), m.channel));
                        }
                        return failed(std::move(rev).error());
                    }
                    undo.push_back(undo_step{existing->second, true});
                }
                modules.emplace_back(name, existing->second);
                continue;
            }
            auto mod = cache_.load_module(box, next.r, i, chunks);
            if (!mod) {
                return failed(std::move(mod).error());
            }
            if (const auto info = box.status(*mod); !info || info->state != script::module_state::kActive) {
                undo.push_back(undo_step{*mod, false});
                return failed(refused(errc::kRuntime, std::format("module '{}' didn't finish loading", name), m.channel));
            }
            undo.push_back(undo_step{*mod, false});
            modules.emplace_back(name, *mod);
        }
        cache_.keep_chunks(box, next.r, chunks, c.running ? &c.running->r : nullptr);
        if (fresh) {
            c.watches.clear();
            c.box = std::move(made); // the old sandbox goes, reverting what the old release did
            c.box_role = m.run_as;
        } else {
            // Modules the new release no longer has, newest first.
            for (auto it = c.modules.rbegin(); it != c.modules.rend(); ++it) {
                if (std::ranges::find(modules, it->first, &std::pair<std::string, module_id>::first) == modules.end()) {
                    (void)box.unload(it->second, script::force);
                }
            }
        }
        c.modules = std::move(modules);
        c.running = next;
        c.handler_failures = 0;
        c.unhealthy.clear();
        return {};
    }

    void tear_down(channel_runtime& c) {
        c.watches.clear();
        c.box.reset();
        c.modules.clear();
        c.running.reset();
        c.active_info.reset();
        c.handler_failures = 0;
        c.unhealthy.clear();
    }

    // After a failed save: runs `before` again (or nothing).
    void put_back(channel_runtime& c, const std::optional<checked_release>& before, const std::optional<release_info>& info) {
        if (before && swap_in(c, *before)) {
            c.active_info = info;
            if (c.state.candidate && *c.state.candidate == before->r.id && c.state.confirm == confirm_mode::kHealth) {
                start_watch(c);
            }
            return;
        }
        tear_down(c);
    }

    // A channel apply() created for a release that never ran there: gone again.
    void forget_if_empty(const std::string& channel, bool created) {
        if (const auto it = channels_.find(channel); created && it != channels_.end() && !it->second.running) {
            channels_.erase(it);
        }
    }

    // Stops the running release. A candidate falls back to the active release (then the previous
    // one), an active release to the previous one; with `hold` nothing runs, and the release it would
    // have fallen back to stays as the previous one. The floor never goes down.
    // `fresh`: the stopped release's sandbox goes first (a revoked release hands nothing to the fallback
    // through on_save).
    void roll_back(channel_runtime& c, std::string reason, bool hold, bool fresh = false) {
        const std::optional<release_id> stopped = c.running ? std::optional<release_id>{c.running->r.id} : std::nullopt;
        const std::uint64_t stopped_seq = c.running ? c.running->r.body.seq : 0;
        if (fresh) {
            tear_down(c);
        }
        std::vector<release_id> chain;
        if (c.state.candidate && stopped && *c.state.candidate == *stopped) {
            for (const auto& id : {c.state.active, c.state.previous}) {
                if (id) {
                    chain.push_back(*id);
                }
            }
            c.state.candidate.reset();
        } else if (c.state.previous) {
            chain.push_back(*c.state.previous);
        }
        c.state.attempts = 0;
        c.state.active.reset();
        c.state.previous.reset();
        c.active_info.reset();
        c.watches.clear();
        c.unhealthy.clear();
        std::optional<release_id> fallback;
        if (hold) {
            tear_down(c);
            for (const release_id& id : chain) { // the first one that could still run
                if (auto r = load_stored(id); r || kept_after_read(r.error())) {
                    c.state.previous = id;
                    break;
                }
            }
        } else {
            std::optional<release_id> kept; // couldn't be read now, may later
            for (std::size_t i = 0; i < chain.size() && !fallback; ++i) {
                auto r = load_stored(chain[i]);
                if (r && swap_in(c, *r)) {
                    fallback = chain[i];
                    c.state.active = chain[i];
                    c.active_info = info_of(*c.running);
                    if (i + 1 < chain.size()) {
                        c.state.previous = chain[i + 1];
                    }
                } else if (!r && kept_after_read(r.error()) && !kept) {
                    kept = chain[i];
                }
            }
            if (!fallback) {
                tear_down(c);
                c.state.previous = kept;
            }
        }
        c.state.held = hold;
        c.state.confirm = confirm_mode::kNow;
        dirty_gc_ = true;
        emit(release_event{release_event::kind::kRolledBack, c.state.name, stopped, fallback, stopped_seq, std::move(reason), std::nullopt});
    }

    void promote_to_active(channel_runtime& c, const release_id& id) {
        if (c.state.active && *c.state.active != id) {
            c.state.previous = c.state.active;
        }
        c.state.active = id;
        if (c.running && c.running->r.id == id) {
            c.active_info = info_of(*c.running);
        }
    }

    // A health-watched candidate runs.
    [[nodiscard]] static bool watched(const channel_runtime& c) noexcept {
        return c.runs_candidate() && c.state.confirm == confirm_mode::kHealth;
    }

    void start_watch(channel_runtime& c) {
        c.watch_started = steady_now();
        c.handler_failures = 0;
        c.unhealthy.clear();
        c.watches.clear();
        if (!c.box || !c.running) {
            return;
        }
        for (const std::string& event : c.running->r.body.health.fail_events) {
            c.watches.push_back(c.box->on_script_event(event, [this, channel = c.state.name, event](const script::script_event&) {
                if (channel_runtime* ch = find(channel); ch != nullptr && ch->unhealthy.empty()) {
                    ch->unhealthy = std::format("unhealthy: '{}' was published", event);
                }
            }));
        }
    }

    // ---- restore ---------------------------------------------------------------------------------

    void quarantine(channel_runtime& c, const release_id& id) {
        if (c.state.quarantined.size() >= kQuarantineKept) {
            c.state.quarantined.erase(c.state.quarantined.begin());
        }
        c.state.quarantined.push_back(id);
        c.state.candidate.reset();
        c.state.attempts = 0;
    }

    // What restore() made of one stored release of a channel.
    enum class restore_outcome : std::uint8_t {
        kRuns,     // it runs
        kDeferred, // it runs nothing this time but is kept (report.deferred): tried again at the next restore
        kGivenUp,  // it can't run (report.failed)
    };

    // Loads stored release `id` into the channel for restore(). A candidate's boot attempt is counted
    // (and saved) before it loads: a crash while it loads counts too, and a candidate whose attempts
    // can't be counted doesn't run (it could crash the program forever).
    restore_outcome try_restore(channel_runtime& c, const release_id& id, bool candidate, restore_report& report) {
        const std::string name = c.state.name;
        auto r = load_stored(id);
        if (!r) {
            if (kept_after_read(r.error())) {
                report.deferred.emplace_back(name, std::move(r).error()); // no attempt used
                return restore_outcome::kDeferred;
            }
            report.failed.emplace_back(name, std::move(r).error());
            return restore_outcome::kGivenUp;
        }
        if (candidate) {
            ++c.state.attempts;
            if (auto saved = persist(); !saved) {
                --c.state.attempts;
                report.deferred.emplace_back(name, save_failed(saved.error(), "its boot attempt couldn't be saved", "release.manager"));
                return restore_outcome::kDeferred;
            }
        }
        if (auto swapped = swap_in(c, *r); !swapped) {
            const bool kept = kept_after_load(swapped.error());
            (kept ? report.deferred : report.failed).emplace_back(name, std::move(swapped).error());
            return kept ? restore_outcome::kDeferred : restore_outcome::kGivenUp;
        }
        return restore_outcome::kRuns;
    }

    void restore_channel(channel_runtime& c, restore_report& report) {
        const std::string name = c.state.name;
        if (c.state.held) {
            return;
        }
        if (c.state.candidate) {
            const release_id candidate = *c.state.candidate;
            if (c.state.attempts >= options_.max_boot_attempts) {
                quarantine(c, candidate);
                report.quarantined.emplace_back(name, candidate);
            } else {
                switch (try_restore(c, candidate, true, report)) {
                case restore_outcome::kRuns:
                    if (c.state.active) {
                        if (auto a = load_stored(*c.state.active)) {
                            c.active_info = info_of(*a);
                        }
                    }
                    if (c.state.confirm == confirm_mode::kHealth) {
                        start_watch(c);
                    }
                    report.restored.push_back(name);
                    return;
                case restore_outcome::kDeferred: return;
                case restore_outcome::kGivenUp:
                    quarantine(c, candidate);
                    report.quarantined.emplace_back(name, candidate);
                    break;
                }
            }
        }
        const std::optional<release_id> active = c.state.active;
        const std::optional<release_id> previous = c.state.previous;
        // A release given up on leaves the state at once, so a later deferral keeps only what may run.
        const auto forget = [&](const std::optional<release_id>& target) {
            if (target == c.state.active) {
                c.state.active.reset();
            } else {
                c.state.previous.reset();
            }
        };
        for (const std::optional<release_id>& target : {active, previous}) {
            if (!target) {
                continue;
            }
            const restore_outcome step = try_restore(c, *target, false, report);
            if (step == restore_outcome::kDeferred) {
                return;
            }
            if (step == restore_outcome::kGivenUp) {
                forget(target);
                continue;
            }
            if (target != active) { // the previous release stands in
                c.state.active = *target;
                c.state.previous.reset();
            }
            c.active_info = info_of(*c.running);
            c.state.confirm = confirm_mode::kNow;
            report.restored.push_back(name);
            return;
        }
        c.state.active.reset();
        c.state.previous.reset();
        c.state.confirm = confirm_mode::kNow;
    }

    // The envelope of release `id` the store holds, decoded (not checked).
    result<release> read_stored(const release_id& id) {
        auto bytes = store_.read(release_key(id));
        if (!bytes) {
            if (bytes.error().code == errc::kNotFound) {
                return fail(errc::kIntegrity, std::format("the store no longer holds release {}", short_id(id)), "release.store");
            }
            return std::unexpected{std::move(bytes).error()};
        }
        auto r = decode_release(*bytes);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        if (r->id != id) {
            return fail(errc::kIntegrity, "a stored release doesn't match its name", "release.store");
        }
        return r;
    }

    result<checked_release> load_stored(const release_id& id) {
        auto r = read_stored(id);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return check(std::move(*r));
    }

    // ---- revocations ---------------------------------------------------------------------------------

    result<std::size_t> take_revocations(std::span<const std::byte> envelope) {
        auto list = decode_revocations(envelope);
        if (!list) {
            return std::unexpected{std::move(list).error()};
        }
        if (list->body.seq <= revoked_.seq) {
            return fail(errc::kSuperseded, std::format("revocation list {} is not newer than {}", list->body.seq, revoked_.seq), "release.revocations");
        }
        // A key any list revoked can't sign a later one (that would forgive itself).
        std::vector<security::ed25519_public_key> excluded = revoked_.keys;
        excluded.insert(excluded.end(), list->body.keys.begin(), list->body.keys.end());
        auto signers = keys_.verify(*list, excluded);
        if (!signers) {
            return std::unexpected{std::move(signers).error()};
        }
        // In effect at once, even if it can't be kept (a revocation only withdraws trust); each list is
        // kept under its own key (restore merges them all), and one that can't be is tried again.
        const std::uint64_t seq = list->body.seq;
        revoked_.merge(list->body);
        for (const seq_floor& f : list->body.floors) {
            raise_floor(f);
        }
        std::size_t changed = 0;
        for (auto& [name, c] : channels_) {
            if (c.state.previous && stored_revoked(*c.state.previous)) {
                c.state.previous.reset();
            }
            const bool runs_active = c.running && c.state.active && c.running->r.id == *c.state.active;
            if (!runs_active && c.state.active && stored_revoked(*c.state.active)) { // a candidate runs: its fallback goes
                c.state.active.reset();
                c.active_info.reset();
            }
            if (c.running && revoked_by_lists(c.running->r)) {
                roll_back(c, "revoked", false, true);
                ++changed;
            }
        }
        unsaved_lists_.emplace_back(revocations_key(seq), std::vector<std::byte>(envelope.begin(), envelope.end()));
        dirty_state_ = true;
        auto saved = persist();
        emit(release_event{release_event::kind::kRevocations, {}, std::nullopt, std::nullopt, revoked_.seq, {}, std::nullopt});
        if (!saved) {
            return std::unexpected{
                save_failed(saved.error(), std::format("revocation list {} is in effect here, but couldn't be saved (tried again later)", seq), "release.revocations")};
        }
        return changed;
    }

    // What the revocation lists say about a release (not its scope, window or libs).
    [[nodiscard]] bool revoked_by_lists(const release& r) const {
        return revoked_.revokes(r.id) || r.body.seq <= revoked_.floor_of(r.body.channel) || !keys_.verify(r, revoked_.keys).has_value();
    }

    // A stored release the lists revoke (one that can't be read is left alone).
    [[nodiscard]] bool stored_revoked(const release_id& id) {
        const auto r = read_stored(id);
        return r && revoked_by_lists(*r);
    }

    // ---- persistence -----------------------------------------------------------------------------------

    result<void> persist() {
        while (!unsaved_lists_.empty()) { // revocation lists first: they hold what the state's union says
            if (auto kept = store_.write(unsaved_lists_.front().first, unsaved_lists_.front().second); !kept) {
                dirty_state_ = true;
                return kept;
            }
            unsaved_lists_.erase(unsaved_lists_.begin());
        }
        std::vector<channel_state> states;
        states.reserve(channels_.size());
        for (const auto& [name, c] : channels_) {
            states.push_back(c.state);
        }
        auto bytes = encode_state(states, revoked_);
        if (!bytes) {
            dirty_state_ = true;
            return std::unexpected{std::move(bytes).error()};
        }
        if (auto written = store_.write(kStateKey, *bytes); !written) {
            dirty_state_ = true;
            return written;
        }
        dirty_state_ = false;
        return {};
    }

    // Removes stored releases (and their bytecode cache entries) no channel names any more (not while
    // the saved state may name others).
    void collect_garbage() {
        if (dirty_state_) {
            return;
        }
        dirty_gc_ = false;
        auto keys = store_.keys();
        if (!keys) {
            return;
        }
        for (const std::string& key : *keys) {
            const bool envelope = key.starts_with(kReleasesPrefix);
            if (!envelope && !key.starts_with(kBytecodePrefix)) {
                continue;
            }
            const bool used = std::ranges::any_of(channels_, [&](const auto& entry) {
                const channel_state& s = entry.second.state;
                for (const auto& id : {s.active, s.previous, s.candidate}) {
                    if (id && (envelope ? release_key(*id) : compiled_store_key(*id)) == key) {
                        return true;
                    }
                }
                return false;
            });
            if (!used) {
                (void)store_.remove(key);
            }
        }
    }

    // ---- helpers --------------------------------------------------------------------------------------

    channel_runtime* find(std::string_view channel) noexcept {
        const auto it = channels_.find(channel);
        return it != channels_.end() ? &it->second : nullptr;
    }

    [[nodiscard]] bool has_lib(std::string_view name) const {
        return std::ranges::any_of(libs_, [&](const auto& l) { return l.first == name; });
    }

    // A floor a revocation list sets: the channel (made if new) never runs a seq at or below it.
    void raise_floor(const seq_floor& f) {
        channel_runtime& c = channels_[f.channel];
        c.state.name = f.channel;
        c.state.floor = std::max(c.state.floor, f.seq);
    }

    [[nodiscard]] static slot current_slot(const channel_runtime& c) noexcept {
        if (!c.running) {
            return slot::kEmpty;
        }
        return c.runs_candidate() ? slot::kCandidate : slot::kActive;
    }

    [[nodiscard]] static release_info info_of(const checked_release& r) {
        return release_info{r.r.id, r.r.body.seq, r.r.body.label, r.signers};
    }

    // manager_options::clock_skew in seconds; a negative skew counts as none.
    [[nodiscard]] std::uint64_t skew_seconds() const noexcept {
        return static_cast<std::uint64_t>(std::max(options_.clock_skew, std::chrono::seconds{0}).count());
    }

    [[nodiscard]] steady::time_point steady_now() const { return options_.clock ? options_.clock() : steady::now(); }
    [[nodiscard]] std::chrono::system_clock::time_point wall_now() const {
        return options_.wall_clock ? options_.wall_clock() : std::chrono::system_clock::now();
    }

    result<apply_result> refuse(std::string_view channel, error err) {
        emit(release_event{release_event::kind::kRefused, std::string{channel}, std::nullopt, std::nullopt, 0, {}, err});
        return std::unexpected{std::move(err)};
    }

    void emit(const release_event& e) noexcept {
        try {
            listeners_->dispatch(e);
        } catch (...) { // a listener's exception must not leave a change half done
        }
    }

    trust keys_;
    manager_options options_;
    any_store store_;
    std::vector<std::pair<std::string, result<void> (*)(script::sandbox&)>> libs_;
    std::map<std::string, channel_runtime, std::less<>> channels_;
    revoked_set revoked_;
    std::shared_ptr<release_listeners> listeners_ = std::make_shared<release_listeners>();
    bool restored_ = false;
    bool dirty_gc_ = false;
    bool dirty_state_ = false; // the last save failed: the store holds an older state
    bool pumping_ = false;     // a channel's sandbox is pumping (its scripts can't call back in)
    steady::time_point retry_at_{};
    std::vector<std::pair<std::string, std::vector<std::byte>>> unsaved_lists_; // revocation lists not stored yet
    std::optional<restore_report> last_restore_;
    compiled_cache cache_{store_, options_.bytecode_key};
};

} // namespace detail

manager::manager(trust keys, manager_options options, any_store store)
    : impl_(std::make_unique<detail::manager_impl>(std::move(keys), std::move(options), std::move(store))) {}
manager::~manager() = default;
manager::manager(manager&&) noexcept = default;
manager& manager::operator=(manager&&) noexcept = default;

result<void> manager::install_lib(std::string_view name, result<void> (*fn)(script::sandbox&)) {
    return impl_->install_lib(name, fn);
}

result<restore_report> manager::restore() {
    return impl_->restore();
}

result<apply_result> manager::apply(std::span<const std::byte> envelope, confirm_mode mode) {
    return impl_->apply(envelope, mode);
}

result<release_id> manager::confirm(std::string_view channel, std::optional<release_id> expected) {
    return impl_->confirm(channel, expected);
}

result<release_id> manager::deactivate(std::string_view channel, bool hold, std::optional<release_id> expected) {
    return impl_->deactivate(channel, hold, expected);
}

result<std::size_t> manager::revoke(std::span<const std::byte> envelope) {
    return impl_->revoke(envelope);
}

std::vector<channel_status> manager::status() const {
    return impl_->status();
}

std::uint64_t manager::revocation_seq() const noexcept {
    return impl_->revocation_seq();
}

const std::optional<restore_report>& manager::last_restore() const noexcept {
    return impl_->last_restore();
}

void manager::pump() {
    impl_->pump();
}

Rhp::subscription manager::on_event(std::function<void(const release_event&)> fn) {
    return impl_->on_event(std::move(fn));
}

script::sandbox* manager::sandbox(std::string_view channel) noexcept {
    return impl_->sandbox(channel);
}

const manager_options& manager::options() const noexcept {
    return impl_->options();
}

bytecode_stats manager::bytecode_cache_stats() const {
    return impl_->bytecode_cache_stats();
}

} // namespace Rhp::release
