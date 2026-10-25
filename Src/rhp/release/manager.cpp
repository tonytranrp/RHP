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
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::release {

std::optional<confirm_mode> parse_confirm_mode(std::string_view text) noexcept {
    for (const confirm_mode m : {confirm_mode::kNow, confirm_mode::kHealth, confirm_mode::kManual}) {
        if (to_string(m) == text) {
            return m;
        }
    }
    return std::nullopt;
}

namespace detail {

namespace {

using steady = std::chrono::steady_clock;

constexpr std::string_view kStateKey = "state";
constexpr std::string_view kRevocationsKey = "revocations";
constexpr std::uint32_t kDefaultWallMs = 10'000;

std::string release_key(const release_id& id) {
    return std::format("releases/{}", to_hex(id));
}

std::uint64_t unix_seconds(std::chrono::system_clock::time_point t) {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return s < 0 ? 0 : static_cast<std::uint64_t>(s);
}

error refused(errc code, std::string message, std::string_view channel) {
    return make_error(code, std::move(message), std::format("release '{}'", channel));
}

// What persists of one channel.
struct channel_state {
    std::string name;
    std::uint64_t floor = 0;
    std::optional<release_id> active;
    std::optional<release_id> previous;
    std::optional<release_id> candidate;
    confirm_mode confirm = confirm_mode::kNow;
    std::uint32_t attempts = 0;
    bool held = false;
    std::vector<release_id> quarantined;
};

value optional_id(const std::optional<release_id>& id) {
    return id ? digest_value(*id) : value{};
}

result<std::optional<release_id>> read_optional_id(const value& v, std::string_view key) {
    if (v.is_nil()) {
        return std::optional<release_id>{};
    }
    auto d = digest(v, key);
    if (!d) {
        return std::unexpected{std::move(d).error()};
    }
    return std::optional<release_id>{*d};
}

// The state document: BLAKE2b-256(body) || body, so a torn or edited file is noticed.
result<std::vector<std::byte>> encode_state(const std::vector<channel_state>& channels, std::uint64_t revocation_seq) {
    value::array list;
    for (const channel_state& c : channels) {
        value::array quarantined;
        for (const release_id& id : c.quarantined) {
            quarantined.push_back(digest_value(id));
        }
        value::map m;
        m.emplace_back(value{"channel"}, value{c.name});
        m.emplace_back(value{"floor"}, value{c.floor});
        m.emplace_back(value{"active"}, optional_id(c.active));
        m.emplace_back(value{"previous"}, optional_id(c.previous));
        m.emplace_back(value{"candidate"}, optional_id(c.candidate));
        m.emplace_back(value{"confirm"}, value{to_string(c.confirm)});
        m.emplace_back(value{"attempts"}, value{c.attempts});
        m.emplace_back(value{"held"}, value{c.held});
        m.emplace_back(value{"quarantined"}, value{std::move(quarantined)});
        list.emplace_back(std::move(m));
    }
    value::map doc;
    doc.emplace_back(value{"rhp"}, value{"release-state"});
    doc.emplace_back(value{"revocation_seq"}, value{revocation_seq});
    doc.emplace_back(value{"channels"}, value{std::move(list)});
    auto body = encode(value{std::move(doc)});
    if (!body) {
        return body;
    }
    const auto check = security::blake2b_256(*body);
    std::vector<std::byte> out(check.begin(), check.end());
    out.insert(out.end(), body->begin(), body->end());
    return out;
}

struct decoded_state {
    std::vector<channel_state> channels;
    std::uint64_t revocation_seq = 0;
};

result<decoded_state> decode_state(std::span<const std::byte> bytes) {
    constexpr std::size_t kCheck = security::digest256{}.size();
    if (bytes.size() < kCheck) {
        return fail(errc::kIntegrity, "the release state is truncated", "release.state");
    }
    const auto body = bytes.subspan(kCheck);
    const auto check = security::blake2b_256(body);
    if (!std::ranges::equal(check, bytes.first(kCheck))) {
        return fail(errc::kIntegrity, "the release state doesn't match its checksum", "release.state");
    }
    auto v = decode(body);
    if (!v) {
        return std::unexpected{std::move(v).error()};
    }
    const value* tag = v->find("rhp");
    if (tag == nullptr || tag->get_if<std::string>() == nullptr || *tag->get_if<std::string>() != "release-state") {
        return std::unexpected{bad_body("not a release state document")};
    }
    decoded_state out;
    if (const value* seq = v->find("revocation_seq"); seq != nullptr) {
        auto n = count(*seq, "revocation_seq");
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        out.revocation_seq = *n;
    }
    const value* channels = v->find("channels");
    const auto* list = channels != nullptr ? channels->get_if<value::array>() : nullptr;
    if (list == nullptr) {
        return std::unexpected{bad_body("the release state has no channels")};
    }
    for (const value& item : *list) {
        channel_state c;
        const auto get = [&](std::string_view key) -> const value& {
            static const value kNil{};
            const value* f = item.find(key);
            return f != nullptr ? *f : kNil;
        };
        auto name = text(get("channel"), "channel");
        auto floor = count(get("floor"), "floor");
        auto active = read_optional_id(get("active"), "active");
        auto previous = read_optional_id(get("previous"), "previous");
        auto candidate = read_optional_id(get("candidate"), "candidate");
        auto confirm = text(get("confirm"), "confirm");
        auto attempts = count(get("attempts"), "attempts");
        if (!name || !floor || !active || !previous || !candidate || !confirm || !attempts || !get("held").is_bool()) {
            return std::unexpected{bad_body("a channel of the release state is malformed")};
        }
        c.name = std::move(*name);
        c.floor = *floor;
        c.active = *active;
        c.previous = *previous;
        c.candidate = *candidate;
        c.confirm = parse_confirm_mode(*confirm).value_or(confirm_mode::kNow);
        c.attempts = static_cast<std::uint32_t>(std::min<std::uint64_t>(*attempts, 1000));
        c.held = *get("held").get_if<bool>();
        if (const auto* q = get("quarantined").get_if<value::array>(); q != nullptr) {
            for (const value& id : *q) {
                if (auto d = digest(id, "quarantined")) {
                    c.quarantined.push_back(*d);
                }
            }
        }
        out.channels.push_back(std::move(c));
    }
    return out;
}

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
};

class manager_impl {
public:
    manager_impl(trust keys, manager_options options, any_store store)
        : keys_(std::move(keys)), options_(std::move(options)), store_(std::move(store)) {
        if (options_.limits.wall_ms == 0) {
            options_.limits.wall_ms = kDefaultWallMs;
        }
    }

    ~manager_impl() {
        for (auto& [name, c] : channels_) {
            c.watches.clear();
            c.box.reset();
        }
    }

    manager_impl(const manager_impl&) = delete;
    manager_impl& operator=(const manager_impl&) = delete;

    result<void> install_lib(std::string_view name, result<void> (*fn)(script::sandbox&)) {
        if (std::ranges::any_of(libs_, [&](const auto& l) { return l.first == name; })) {
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

    void on_event(std::function<void(const release_event&)> fn) { on_event_ = std::move(fn); }
    [[nodiscard]] const manager_options& options() const noexcept { return options_; }
    [[nodiscard]] std::uint64_t revocation_seq() const noexcept { return revocations_ ? revocations_->body.seq : 0; }

    script::sandbox* sandbox(std::string_view channel) noexcept {
        const auto it = channels_.find(channel);
        return it != channels_.end() ? it->second.box.get() : nullptr;
    }

    // ---- restore ---------------------------------------------------------------------------------

    result<restore_report> restore() {
        if (restored_) {
            return fail(errc::kAlreadyLoaded, "restore() runs once, before the first apply()", "release.manager");
        }
        restored_ = true;
        restore_report report;
        if (auto rev = store_.read(kRevocationsKey); rev) {
            if (auto applied = take_revocations(*rev, false); !applied) {
                report.failed.emplace_back("*", applied.error());
            }
        }
        auto bytes = store_.read(kStateKey);
        if (!bytes) {
            if (bytes.error().code == errc::kNotFound) {
                return report; // a first start
            }
            return std::unexpected{std::move(bytes).error()};
        }
        auto state = decode_state(*bytes);
        if (!state) {
            return std::unexpected{std::move(state).error()};
        }
        if (state->revocation_seq > revocation_seq()) {
            // The state saw a newer list than the store holds now: refuse to forget revocations.
            report.failed.emplace_back("*", make_error(errc::kIntegrity, "the stored revocation list is older than the state says", "release.manager"));
        }
        for (channel_state& s : state->channels) {
            channel_runtime& c = channels_[s.name];
            c.state = std::move(s);
            restore_channel(c, report);
        }
        persist();
        collect_garbage();
        return report;
    }

    // ---- apply -------------------------------------------------------------------------------------

    result<apply_result> apply(std::span<const std::byte> envelope, confirm_mode mode) {
        restored_ = true;
        auto decoded = decode_release(envelope);
        if (!decoded) {
            return refuse("", std::move(decoded).error());
        }
        release& r = *decoded;
        const std::string channel = r.body.channel;
        if (!r.revocations.empty()) {
            if (auto rev = take_revocations(r.revocations, true); !rev && rev.error().code != errc::kSuperseded) {
                return refuse(channel, std::move(rev).error());
            }
        }
        auto checked = check(std::move(r));
        if (!checked) {
            return refuse(channel, std::move(checked).error());
        }
        channel_runtime& c = channels_[channel];
        c.state.name = channel;
        const release_id id = checked->r.id;
        const std::uint64_t seq = checked->r.body.seq;
        if (c.running && c.running->r.id == id) {
            apply_result same{channel, id, seq, current_slot(c), true, std::nullopt, checked->signers};
            return same;
        }
        if (seq <= c.state.floor) {
            return refuse(channel, refused(errc::kSuperseded, std::format("seq {} is not above the channel's floor {}", seq, c.state.floor), channel));
        }
        if (c.state.floor != 0 && seq - c.state.floor > options_.max_seq_jump) {
            return refuse(channel, refused(errc::kOutOfRange, std::format("seq {} jumps more than {} past {}", seq, options_.max_seq_jump, c.state.floor), channel));
        }
        if (std::ranges::find(c.state.quarantined, id) != c.state.quarantined.end()) {
            return refuse(channel, refused(errc::kRevoked, "this release was quarantined on this host", channel));
        }
        // Keep the envelope first: the state never names a release the store doesn't hold.
        auto bytes = encode_release(checked->r);
        if (!bytes) {
            return refuse(channel, std::move(bytes).error());
        }
        if (auto kept = store_.write(release_key(id), *bytes); !kept) {
            return refuse(channel, std::move(kept).error());
        }
        const std::optional<release_id> replaced = c.running ? std::optional<release_id>{c.running->r.id} : std::nullopt;
        if (auto swapped = swap_in(c, *checked); !swapped) {
            collect_garbage();
            return refuse(channel, std::move(swapped).error());
        }
        c.state.floor = seq;
        c.state.held = false;
        if (mode == confirm_mode::kNow) {
            promote_to_active(c, id);
            c.state.candidate.reset();
        } else {
            c.state.candidate = id;
            c.state.attempts = 0;
            start_watch(c);
        }
        c.state.confirm = mode;
        persist();
        collect_garbage();
        apply_result out{channel, id, seq, current_slot(c), false, replaced, c.running->signers};
        emit(release_event{release_event::kind::kApplied, channel, id, std::nullopt, seq, {}, std::nullopt});
        return out;
    }

    // ---- confirm / deactivate ---------------------------------------------------------------------

    result<void> confirm(std::string_view channel) {
        channel_runtime* c = find(channel);
        if (c == nullptr || !c->state.candidate) {
            return fail(errc::kNotFound, std::format("channel '{}' has no candidate", channel), "release.manager");
        }
        const release_id id = *c->state.candidate;
        promote_to_active(*c, id);
        c->state.candidate.reset();
        c->state.attempts = 0;
        c->watches.clear();
        persist();
        collect_garbage();
        emit(release_event{release_event::kind::kConfirmed, std::string{channel}, id, std::nullopt, c->running ? c->running->r.body.seq : 0, {}, std::nullopt});
        return {};
    }

    result<void> deactivate(std::string_view channel, bool hold) {
        channel_runtime* c = find(channel);
        if (c == nullptr || !c->running) {
            return fail(errc::kNotFound, std::format("nothing runs in channel '{}'", channel), "release.manager");
        }
        roll_back(*c, hold ? "deactivated (held)" : "deactivated", hold);
        persist();
        collect_garbage();
        return {};
    }

    // ---- revocations ---------------------------------------------------------------------------------

    result<std::size_t> revoke(std::span<const std::byte> envelope) {
        restored_ = true;
        auto changed = take_revocations(envelope, true);
        if (!changed) {
            return changed;
        }
        persist();
        collect_garbage();
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
            if (c.state.candidate && c.running && c.running->r.id == *c.state.candidate) {
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
        const auto skew = static_cast<std::uint64_t>(options_.clock_skew.count());
        for (auto& [name, c] : channels_) {
            if (c.box) {
                c.box->pump();
            }
            if (!c.running) {
                continue;
            }
            const manifest& m = c.running->r.body;
            if (options_.expire_running && m.not_after != 0 && wall > m.not_after + skew) {
                roll_back(c, "expired", false);
                persist();
                continue;
            }
            if (!c.state.candidate || c.state.confirm != confirm_mode::kHealth) {
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
                persist();
            } else if (now - c.watch_started >= options_.health_window) {
                (void)confirm(name);
            }
        }
        if (dirty_gc_) {
            collect_garbage();
        }
    }

private:
    // ---- checks ------------------------------------------------------------------------------------

    result<checked_release> check(release r) const {
        const std::string_view channel = r.body.channel;
        std::vector<security::ed25519_public_key> revoked_keys;
        if (revocations_) {
            revoked_keys = revocations_->body.keys;
            if (std::ranges::find(revocations_->body.releases, r.id) != revocations_->body.releases.end()) {
                return std::unexpected{refused(errc::kRevoked, "this release is revoked", channel)};
            }
        }
        auto signers = keys_.verify(r, revoked_keys);
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
        const auto skew = static_cast<std::uint64_t>(options_.clock_skew.count());
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
            if (!std::ranges::any_of(libs_, [&](const auto& l) { return l.first == lib; })) {
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
            if (channel_runtime* c = find(channel)) {
                ++c->handler_failures;
            }
        };
        auto box = std::make_unique<script::sandbox>(std::move(o));
        for (const auto& [name, fn] : libs_) {
            (void)fn(*box);
        }
        return box;
    }

    // Loads `next`'s modules into the channel. The old release keeps running if anything fails.
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
        const auto compensate = [&] {
            for (auto it = undo.rbegin(); it != undo.rend(); ++it) {
                if (it->reloaded) {
                    (void)box.rollback(it->mod, 1);
                } else {
                    (void)box.unload(it->mod, script::force);
                }
            }
        };
        for (std::size_t i = 0; i < m.modules.size(); ++i) {
            const std::string& name = m.modules[i].name;
            const std::string& source = next.r.sources[i];
            const auto existing = std::ranges::find(c.modules, name, &std::pair<std::string, module_id>::first);
            if (!fresh && existing != c.modules.end()) {
                const bool same = c.running && i < c.running->r.body.modules.size() && c.running->r.body.modules[i].name == name &&
                                  c.running->r.body.modules[i].hash == m.modules[i].hash;
                if (!same) {
                    auto rev = box.reload(existing->second, source);
                    if (!rev || *rev == revision_id{}) {
                        if (rev) { // suspended in its top level: not a release's module
                            (void)box.rollback(existing->second, 1);
                        }
                        compensate();
                        return std::unexpected{rev ? refused(errc::kRuntime, std::format("module '{}' suspended while loading", name), m.channel)
                                                   : std::move(rev).error()};
                    }
                    undo.push_back(undo_step{existing->second, true});
                }
                modules.emplace_back(name, existing->second);
                continue;
            }
            auto mod = box.load(name, source);
            if (!mod) {
                compensate();
                return std::unexpected{std::move(mod).error()};
            }
            if (const auto info = box.status(*mod); !info || info->state != script::module_state::kActive) {
                (void)box.unload(*mod, script::force);
                compensate();
                return std::unexpected{refused(errc::kRuntime, std::format("module '{}' didn't finish loading", name), m.channel)};
            }
            undo.push_back(undo_step{*mod, false});
            modules.emplace_back(name, *mod);
        }
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

    // Stops the running release: a candidate falls back to the active one, an active one to the
    // previous (unless `hold`, or the fallback can't run).
    void roll_back(channel_runtime& c, std::string reason, bool hold) {
        const std::optional<release_id> stopped = c.running ? std::optional<release_id>{c.running->r.id} : std::nullopt;
        std::optional<release_id> fallback;
        if (c.state.candidate && stopped && *c.state.candidate == *stopped) {
            c.state.candidate.reset();
            c.state.attempts = 0;
            fallback = c.state.active;
        } else {
            fallback = c.state.previous;
            c.state.active = c.state.previous;
            c.state.previous.reset();
            c.active_info.reset();
        }
        c.watches.clear();
        bool running_fallback = false;
        if (!hold && fallback) {
            if (auto r = load_stored(*fallback); r) {
                running_fallback = swap_in(c, *r).has_value();
                if (running_fallback) {
                    c.state.active = *fallback;
                    c.active_info = info_of(*c.running);
                }
            }
        }
        if (!running_fallback) {
            c.box.reset();
            c.modules.clear();
            c.running.reset();
            c.active_info.reset();
            c.state.active.reset();
            fallback.reset();
        }
        c.state.held = hold;
        c.state.confirm = confirm_mode::kNow;
        dirty_gc_ = true;
        emit(release_event{release_event::kind::kRolledBack, c.state.name, stopped, fallback, 0, std::move(reason), std::nullopt});
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

    void restore_channel(channel_runtime& c, restore_report& report) {
        const std::string name = c.state.name;
        if (c.state.held) {
            return;
        }
        if (c.state.candidate) {
            const release_id candidate = *c.state.candidate;
            if (c.state.attempts + 1 >= options_.max_boot_attempts + 1) {
                c.state.quarantined.push_back(candidate);
                c.state.candidate.reset();
                c.state.attempts = 0;
                report.quarantined.emplace_back(name, candidate);
            } else {
                ++c.state.attempts;
                persist(); // counted before it runs: a crash while it loads counts too
                if (auto r = load_stored(candidate); r) {
                    if (auto swapped = swap_in(c, *r); swapped) {
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
                    } else {
                        report.failed.emplace_back(name, std::move(swapped).error());
                    }
                } else {
                    report.failed.emplace_back(name, std::move(r).error());
                }
                c.state.quarantined.push_back(candidate);
                c.state.candidate.reset();
                c.state.attempts = 0;
            }
        }
        for (const std::optional<release_id> target : {c.state.active, c.state.previous}) {
            if (!target) {
                continue;
            }
            auto r = load_stored(*target);
            if (!r) {
                report.failed.emplace_back(name, std::move(r).error());
                continue;
            }
            if (auto swapped = swap_in(c, *r); !swapped) {
                report.failed.emplace_back(name, std::move(swapped).error());
                continue;
            }
            if (target != c.state.active) { // the previous release stands in
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
    }

    result<checked_release> load_stored(const release_id& id) {
        auto bytes = store_.read(release_key(id));
        if (!bytes) {
            return std::unexpected{std::move(bytes).error()};
        }
        auto r = decode_release(*bytes);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        if (r->id != id) {
            return fail(errc::kIntegrity, "a stored release doesn't match its name", "release.store");
        }
        return check(std::move(*r));
    }

    // ---- revocations ---------------------------------------------------------------------------------

    result<std::size_t> take_revocations(std::span<const std::byte> envelope, bool keep) {
        auto list = decode_revocations(envelope);
        if (!list) {
            return std::unexpected{std::move(list).error()};
        }
        if (list->body.seq <= revocation_seq()) {
            return fail(errc::kSuperseded, std::format("revocation list {} is not newer than {}", list->body.seq, revocation_seq()), "release.revocations");
        }
        auto signers = keys_.verify(*list, list->body.keys);
        if (!signers) {
            return std::unexpected{std::move(signers).error()};
        }
        if (keep) {
            if (auto kept = store_.write(kRevocationsKey, envelope); !kept) {
                return std::unexpected{std::move(kept).error()};
            }
        }
        revocations_ = std::move(*list);
        std::size_t changed = 0;
        for (auto& [name, c] : channels_) {
            for (const seq_floor& f : revocations_->body.floors) {
                if (f.channel == name && f.seq > c.state.floor) {
                    c.state.floor = f.seq;
                }
            }
            const auto revoked = [&](const std::optional<release_id>& id) {
                return id && std::ranges::find(revocations_->body.releases, *id) != revocations_->body.releases.end();
            };
            if (revoked(c.state.previous)) {
                c.state.previous.reset();
            }
            bool stop = c.running && revoked(std::optional<release_id>{c.running->r.id});
            if (c.running && !stop) { // signed only by keys revoked now?
                stop = !keys_.verify(c.running->r, revocations_->body.keys).has_value();
            }
            if (stop) {
                roll_back(c, "revoked", false);
                ++changed;
            }
        }
        // Floors for channels nothing ran in yet.
        for (const seq_floor& f : revocations_->body.floors) {
            channel_runtime& c = channels_[f.channel];
            c.state.name = f.channel;
            c.state.floor = std::max(c.state.floor, f.seq);
        }
        if (keep) {
            persist();
        }
        emit(release_event{release_event::kind::kRevocations, {}, std::nullopt, std::nullopt, revocations_->body.seq, {}, std::nullopt});
        return changed;
    }

    // ---- persistence -----------------------------------------------------------------------------------

    void persist() {
        std::vector<channel_state> states;
        for (const auto& [name, c] : channels_) {
            states.push_back(c.state);
        }
        if (auto bytes = encode_state(states, revocation_seq()); bytes) {
            (void)store_.write(kStateKey, *bytes);
        }
    }

    // Removes stored releases no channel names any more.
    void collect_garbage() {
        dirty_gc_ = false;
        auto keys = store_.keys();
        if (!keys) {
            return;
        }
        for (const std::string& key : *keys) {
            if (!key.starts_with("releases/")) {
                continue;
            }
            const bool used = std::ranges::any_of(channels_, [&](const auto& entry) {
                const channel_state& s = entry.second.state;
                for (const auto& id : {s.active, s.previous, s.candidate}) {
                    if (id && release_key(*id) == key) {
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

    [[nodiscard]] static slot current_slot(const channel_runtime& c) noexcept {
        if (!c.running) {
            return slot::kEmpty;
        }
        return c.state.candidate && c.running->r.id == *c.state.candidate ? slot::kCandidate : slot::kActive;
    }

    [[nodiscard]] static release_info info_of(const checked_release& r) {
        return release_info{r.r.id, r.r.body.seq, r.r.body.label, r.signers};
    }

    [[nodiscard]] steady::time_point steady_now() const { return options_.clock ? options_.clock() : steady::now(); }
    [[nodiscard]] std::chrono::system_clock::time_point wall_now() const {
        return options_.wall_clock ? options_.wall_clock() : std::chrono::system_clock::now();
    }

    result<apply_result> refuse(std::string_view channel, error err) {
        emit(release_event{release_event::kind::kRefused, std::string{channel}, std::nullopt, std::nullopt, 0, {}, err});
        return std::unexpected{std::move(err)};
    }

    void emit(const release_event& e) {
        if (on_event_) {
            on_event_(e);
        }
    }

    trust keys_;
    manager_options options_;
    any_store store_;
    std::vector<std::pair<std::string, result<void> (*)(script::sandbox&)>> libs_;
    std::map<std::string, channel_runtime, std::less<>> channels_;
    std::optional<signed_revocations> revocations_;
    std::function<void(const release_event&)> on_event_;
    bool restored_ = false;
    bool dirty_gc_ = false;
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

result<void> manager::confirm(std::string_view channel) {
    return impl_->confirm(channel);
}

result<void> manager::deactivate(std::string_view channel, bool hold) {
    return impl_->deactivate(channel, hold);
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

void manager::pump() {
    impl_->pump();
}

void manager::on_event(std::function<void(const release_event&)> fn) {
    impl_->on_event(std::move(fn));
}

script::sandbox* manager::sandbox(std::string_view channel) noexcept {
    return impl_->sandbox(channel);
}

const manager_options& manager::options() const noexcept {
    return impl_->options();
}

} // namespace Rhp::release
