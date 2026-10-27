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
#include <rhp/core/value.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::release {

namespace detail {

namespace {

using steady = std::chrono::steady_clock;

constexpr std::string_view kStateKey = "state";
constexpr std::string_view kRevocationsKey = "revocations"; // the newest list (stores written before every list was kept)
constexpr std::string_view kRevocationsPrefix = "revocations/"; // every accepted list, by seq
constexpr std::uint32_t kDefaultWallMs = 10'000;
constexpr std::size_t kQuarantineKept = 16; // newest quarantined ids a channel remembers

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

error refused(errc code, std::string message, std::string_view channel) {
    return make_error(code, std::move(message), std::format("release '{}'", channel));
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

// Everything every revocation list applied so far withdrew: lists only ever add to it, so a newer
// list can't forgive what an older one revoked (not even one signed by a key that older list revoked).
struct revoked_set {
    std::uint64_t seq = 0; // the newest list applied
    std::vector<release_id> releases;
    std::vector<security::ed25519_public_key> keys;
    std::vector<seq_floor> floors; // per channel: releases at or below it are revoked

    void merge(const revocation_list& l) {
        seq = std::max(seq, l.seq);
        for (const release_id& id : l.releases) {
            if (std::ranges::find(releases, id) == releases.end()) {
                releases.push_back(id);
            }
        }
        for (const auto& k : l.keys) {
            if (std::ranges::find(keys, k) == keys.end()) {
                keys.push_back(k);
            }
        }
        for (const seq_floor& f : l.floors) {
            const auto it = std::ranges::find(floors, f.channel, &seq_floor::channel);
            if (it == floors.end()) {
                floors.push_back(f);
            } else {
                it->seq = std::max(it->seq, f.seq);
            }
        }
    }

    void merge(const revoked_set& o) {
        revocation_list l;
        l.seq = o.seq;
        l.releases = o.releases;
        l.keys = o.keys;
        l.floors = o.floors;
        merge(l);
    }

    [[nodiscard]] bool revokes(const release_id& id) const { return std::ranges::find(releases, id) != releases.end(); }

    [[nodiscard]] std::uint64_t floor_of(std::string_view channel) const {
        const auto it = std::ranges::find(floors, channel, &seq_floor::channel);
        return it != floors.end() ? it->seq : 0;
    }
};

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

// The state document: BLAKE2b-256(body) || body. The checksum notices a torn or corrupted file, not
// a deliberate edit: whoever can write the store can lower floors (signatures are still checked on
// every restore, so only signed releases ever run).
result<std::vector<std::byte>> encode_state(const std::vector<channel_state>& channels, const revoked_set& revoked) {
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
    value::array ids;
    for (const release_id& id : revoked.releases) {
        ids.push_back(digest_value(id));
    }
    value::array keys;
    for (const auto& k : revoked.keys) {
        keys.emplace_back(value::bytes(k.bytes().begin(), k.bytes().end()));
    }
    value::array floors;
    for (const seq_floor& f : revoked.floors) {
        value::map m;
        m.emplace_back(value{"channel"}, value{f.channel});
        m.emplace_back(value{"seq"}, value{f.seq});
        floors.emplace_back(std::move(m));
    }
    value::map doc;
    doc.emplace_back(value{"rhp"}, value{"release-state"});
    doc.emplace_back(value{"revocation_seq"}, value{revoked.seq});
    doc.emplace_back(value{"revoked_releases"}, value{std::move(ids)});
    doc.emplace_back(value{"revoked_keys"}, value{std::move(keys)});
    doc.emplace_back(value{"revoked_floors"}, value{std::move(floors)});
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
    revoked_set revoked;
};

result<revoked_set> decode_revoked(const value& doc) {
    revoked_set out;
    if (const value* seq = doc.find("revocation_seq"); seq != nullptr) {
        auto n = count(*seq, "revocation_seq");
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        out.seq = *n;
    }
    if (const value* ids = doc.find("revoked_releases"); ids != nullptr && ids->get_if<value::array>() != nullptr) {
        for (const value& id : *ids->get_if<value::array>()) {
            auto d = digest(id, "revoked_releases");
            if (!d) {
                return std::unexpected{std::move(d).error()};
            }
            out.releases.push_back(*d);
        }
    }
    if (const value* keys = doc.find("revoked_keys"); keys != nullptr && keys->get_if<value::array>() != nullptr) {
        for (const value& k : *keys->get_if<value::array>()) {
            const auto* raw = k.get_if<value::bytes>();
            auto key = raw != nullptr ? security::ed25519_public_key::from_bytes(*raw)
                                      : result<security::ed25519_public_key>{std::unexpected{bad_body("a revoked key is not bytes")}};
            if (!key) {
                return std::unexpected{std::move(key).error()};
            }
            out.keys.push_back(*key);
        }
    }
    if (const value* floors = doc.find("revoked_floors"); floors != nullptr && floors->get_if<value::array>() != nullptr) {
        for (const value& f : *floors->get_if<value::array>()) {
            const value* channel = f.find("channel");
            const value* seq = f.find("seq");
            auto name = channel != nullptr ? text(*channel, "channel") : result<std::string>{std::unexpected{bad_body("a revoked floor has no channel")}};
            auto n = seq != nullptr ? count(*seq, "seq") : result<std::uint64_t>{std::unexpected{bad_body("a revoked floor has no seq")}};
            if (!name || !n) {
                return std::unexpected{bad_body("a revoked floor of the release state is malformed")};
            }
            out.floors.push_back(seq_floor{std::move(*name), *n});
        }
    }
    return out;
}

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
    auto revoked = decode_revoked(*v);
    if (!revoked) {
        return std::unexpected{std::move(revoked).error()};
    }
    out.revoked = std::move(*revoked);
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
            if (c.quarantined.size() > kQuarantineKept) { // the newest
                c.quarantined.erase(c.quarantined.begin(), c.quarantined.end() - static_cast<std::ptrdiff_t>(kQuarantineKept));
            }
        }
        out.channels.push_back(std::move(c));
    }
    return out;
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

// The bytecode one swap loads a release's modules from (the compiled-chunk cache), and what it
// compiled for the cache meanwhile.
struct chunk_set {
    std::optional<compiled_release> stored; // the release's entry from the store, checked
    std::vector<std::string> made;          // per module: compiled here
    std::vector<char> refused;              // per module: Lua refused the stored bytecode (the source was parsed)

    [[nodiscard]] std::string_view stored_code(std::size_t i) const noexcept {
        if (!stored || i >= stored->modules.size() || refused[i] != 0) {
            return {};
        }
        const std::vector<std::byte>& code = stored->modules[i].code;
        return std::string_view{reinterpret_cast<const char*>(code.data()), code.size()};
    }
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
        build_ = compiled_build();
        caching_ = !options_.bytecode_key.empty() && build_ != security::digest256{};
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

    Rhp::subscription on_event(std::function<void(const release_event&)> fn) {
        const std::uint64_t id = listeners_->add(std::move(fn));
        return Rhp::subscription{listeners_, id};
    }

    [[nodiscard]] const manager_options& options() const noexcept { return options_; }
    [[nodiscard]] std::uint64_t revocation_seq() const noexcept { return revoked_.seq; }
    [[nodiscard]] const bytecode_stats& bytecode_cache_stats() const noexcept { return cache_stats_; }

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
            channel_runtime& c = channels_[f.channel];
            c.state.name = f.channel;
            c.state.floor = std::max(c.state.floor, f.seq);
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
            c.unhealthy.clear();
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
            return refuse(channel, refused(saved.error().code, std::format("the release state couldn't be saved: {}", saved.error().message), channel));
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
        if (c == nullptr || !c->state.candidate || !c->running || c->running->r.id != *c->state.candidate) {
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
            return fail(saved.error().code, std::format("the release state couldn't be saved: {}", saved.error().message), "release.manager");
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
            return fail(saved.error().code, std::format("deactivated, but the release state couldn't be saved: {}", saved.error().message), "release.manager");
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
                pumping_ = true; // a channel's script calling back into the manager is refused
                try {
                    c.box->pump();
                } catch (...) {
                    pumping_ = false;
                    throw;
                }
                pumping_ = false;
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
        chunk_set chunks = cached_chunks(next.r);
        for (std::size_t i = 0; i < m.modules.size(); ++i) {
            const std::string& name = m.modules[i].name;
            const auto existing = std::ranges::find(c.modules, name, &std::pair<std::string, module_id>::first);
            if (!fresh && existing != c.modules.end()) {
                const bool same = c.running && i < c.running->r.body.modules.size() && c.running->r.body.modules[i].name == name &&
                                  c.running->r.body.modules[i].hash == m.modules[i].hash;
                if (!same) {
                    auto rev = reload_module(box, existing->second, next.r, i, chunks);
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
            auto mod = load_module(box, next.r, i, chunks);
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
        keep_chunks(box, next.r, chunks, c.running ? &c.running->r : nullptr);
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

    // ---- compiled-chunk cache ----------------------------------------------------------------------
    // Bytecode is only ever read from the store, and only after its MAC checks out under the host's
    // key; envelopes from the wire are parsed (text). See bytecode.hpp.

    // What a swap of `r` loads from: its checked entry, or nothing (the cache is off, there is none,
    // or it was thrown away).
    chunk_set cached_chunks(const release& r) {
        chunk_set out;
        out.made.resize(r.sources.size());
        out.refused.resize(r.sources.size(), 0);
        if (!caching_) {
            return out;
        }
        auto bytes = store_.read(compiled_store_key(r.id));
        if (!bytes) {
            return out; // none yet (or unreadable right now): compiled here
        }
        auto entry = check_entry(*bytes, r);
        if (!entry) {
            discard(r.id, std::move(entry).error());
            return out;
        }
        out.stored = std::move(*entry);
        return out;
    }

    // An entry whose MAC checks out, made by this Lua build for exactly `r`'s modules.
    result<compiled_release> check_entry(std::span<const std::byte> bytes, const release& r) const {
        auto entry = open_compiled(bytes, options_.bytecode_key);
        if (!entry) {
            return entry;
        }
        if (entry->build != build_) {
            return fail(errc::kOutOfScope, "a bytecode cache entry was made by another Lua build", "release.bytecode");
        }
        const std::vector<module_entry>& mods = r.body.modules;
        bool same = entry->release == r.id && entry->modules.size() == mods.size();
        for (std::size_t i = 0; same && i < mods.size(); ++i) {
            same = entry->modules[i].name == mods[i].name && entry->modules[i].hash == mods[i].hash;
        }
        if (!same) {
            return fail(errc::kIntegrity, std::format("a bytecode cache entry doesn't hold release {}'s modules", short_id(r.id)), "release.bytecode");
        }
        return entry;
    }

    void discard(const release_id& id, error why) {
        (void)store_.remove(compiled_store_key(id));
        ++cache_stats_.discarded;
        cache_stats_.last_discarded = std::move(why);
    }

    // The bytecode to load module i of `r` from: the stored entry's, else (the cache on) compiled here
    // and kept in `chunks`; empty: parse the source.
    std::string_view bytecode_for(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks) {
        if (const std::string_view code = chunks.stored_code(i); !code.empty()) {
            return code;
        }
        if (!caching_) {
            return {};
        }
        auto made = box.compile_module(r.body.modules[i].name, r.sources[i]);
        if (!made) {
            return {}; // loading the source reports why
        }
        ++cache_stats_.compiled;
        chunks.made[i] = std::move(*made);
        return chunks.made[i];
    }

    // Runs a load given bytecode; notes whether Lua refused stored bytecode (the sandbox parsed the source).
    template <class F>
    auto tracked(script::sandbox& box, std::size_t i, chunk_set& chunks, F&& load) {
        const bool from_store = !chunks.stored_code(i).empty();
        const std::uint64_t refused_before = box.stats().bytecode_rejected;
        auto out = load();
        if (box.stats().bytecode_rejected != refused_before) {
            chunks.refused[i] = 1;
        } else if (from_store) {
            ++cache_stats_.loaded;
        }
        return out;
    }

    result<module_id> load_module(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks) {
        const std::string& name = r.body.modules[i].name;
        const std::string_view code = bytecode_for(box, r, i, chunks);
        if (code.empty()) {
            return box.load(name, r.sources[i]);
        }
        return tracked(box, i, chunks, [&] { return box.load(name, r.sources[i], script::trusted_bytecode{code}); });
    }

    result<revision_id> reload_module(script::sandbox& box, module_id mod, const release& r, std::size_t i, chunk_set& chunks) {
        const std::string_view code = bytecode_for(box, r, i, chunks);
        if (code.empty()) {
            return box.reload(mod, r.sources[i]);
        }
        return tracked(box, i, chunks, [&] { return box.reload(mod, r.sources[i], script::trusted_bytecode{code}); });
    }

    // After a swap loaded `r`: stores its entry unless the store's served every module. Modules the
    // swap didn't load (unchanged since `before`) take their bytecode from `before`'s entry, else are
    // compiled here (parsed, nothing runs). Failing to store only costs the next load a parse.
    void keep_chunks(script::sandbox& box, const release& r, const chunk_set& chunks, const release* before) {
        if (!caching_) {
            return;
        }
        const bool refused = std::ranges::any_of(chunks.refused, [](char x) { return x != 0; });
        if (chunks.stored && !refused) {
            return;
        }
        if (refused) {
            discard(r.id, make_error(errc::kIntegrity, "Lua refused a module's cached bytecode", "release.bytecode"));
        }
        std::optional<compiled_release> prior;
        bool prior_read = false;
        compiled_release entry;
        entry.release = r.id;
        entry.build = build_;
        for (std::size_t i = 0; i < r.body.modules.size(); ++i) {
            const module_entry& m = r.body.modules[i];
            std::vector<std::byte> code;
            if (!chunks.made[i].empty()) {
                const auto bytes = utils::as_bytes(chunks.made[i]);
                code.assign(bytes.begin(), bytes.end());
            } else if (const std::string_view stored = chunks.stored_code(i); !stored.empty()) {
                code = chunks.stored->modules[i].code;
            } else {
                if (before != nullptr && !prior_read && chunks.refused[i] == 0) {
                    prior_read = true;
                    if (auto bytes = store_.read(compiled_store_key(before->id))) {
                        if (auto e = check_entry(*bytes, *before)) {
                            prior = std::move(*e);
                        }
                    }
                }
                if (prior && chunks.refused[i] == 0) {
                    for (const compiled_module& p : prior->modules) {
                        if (p.name == m.name && p.hash == m.hash) {
                            code = p.code;
                            break;
                        }
                    }
                }
                if (code.empty()) {
                    auto made = box.compile_module(m.name, r.sources[i]);
                    if (!made) {
                        return;
                    }
                    ++cache_stats_.compiled;
                    const auto bytes = utils::as_bytes(*made);
                    code.assign(bytes.begin(), bytes.end());
                }
            }
            entry.modules.push_back(compiled_module{m.name, m.hash, std::move(code)});
        }
        auto sealed = seal_compiled(entry, options_.bytecode_key);
        if (!sealed || !store_.write(compiled_store_key(r.id), *sealed)) {
            ++cache_stats_.store_failures;
            return;
        }
        ++cache_stats_.stored;
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
        return c.state.candidate && c.state.confirm == confirm_mode::kHealth && c.running && c.running->r.id == *c.state.candidate;
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
                auto r = load_stored(candidate);
                if (!r && kept_after_read(r.error())) {
                    report.deferred.emplace_back(name, std::move(r).error()); // runs nothing this time; no attempt used
                    return;
                }
                if (r) {
                    // Counted before it loads: a crash while it loads counts too. A candidate whose
                    // attempts can't be counted doesn't run (it could crash the program forever).
                    ++c.state.attempts;
                    if (auto saved = persist(); !saved) {
                        --c.state.attempts;
                        report.deferred.emplace_back(name, make_error(saved.error().code, std::format("its boot attempt couldn't be saved: {}", saved.error().message),
                                                                      "release.manager"));
                        return;
                    }
                    auto swapped = swap_in(c, *r);
                    if (swapped) {
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
                    }
                    if (kept_after_load(swapped.error())) {
                        report.deferred.emplace_back(name, std::move(swapped).error());
                        return;
                    }
                    report.failed.emplace_back(name, std::move(swapped).error());
                } else {
                    report.failed.emplace_back(name, std::move(r).error());
                }
                quarantine(c, candidate);
                report.quarantined.emplace_back(name, candidate);
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
            auto r = load_stored(*target);
            if (!r && kept_after_read(r.error())) {
                report.deferred.emplace_back(name, std::move(r).error()); // runs nothing this time; kept
                return;
            }
            if (!r) {
                report.failed.emplace_back(name, std::move(r).error());
                forget(target);
                continue;
            }
            if (auto swapped = swap_in(c, *r); !swapped) {
                if (kept_after_load(swapped.error())) {
                    report.deferred.emplace_back(name, std::move(swapped).error());
                    return;
                }
                report.failed.emplace_back(name, std::move(swapped).error());
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

    result<checked_release> load_stored(const release_id& id) {
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
            channel_runtime& c = channels_[f.channel];
            c.state.name = f.channel;
            c.state.floor = std::max(c.state.floor, f.seq);
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
            return fail(saved.error().code, std::format("revocation list {} is in effect here, but couldn't be saved (tried again later): {}", seq, saved.error().message),
                        "release.revocations");
        }
        return changed;
    }

    // What the revocation lists say about a release (not its scope, window or libs).
    [[nodiscard]] bool revoked_by_lists(const release& r) const {
        return revoked_.revokes(r.id) || r.body.seq <= revoked_.floor_of(r.body.channel) || !keys_.verify(r, revoked_.keys).has_value();
    }

    // A stored release the lists revoke (one that can't be read is left alone).
    [[nodiscard]] bool stored_revoked(const release_id& id) {
        auto bytes = store_.read(release_key(id));
        if (!bytes) {
            return false;
        }
        auto r = decode_release(*bytes);
        return r && r->id == id && revoked_by_lists(*r);
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
    security::digest256 build_{}; // compiled_build()
    bool caching_ = false;        // a bytecode key, and a build to key entries by
    bytecode_stats cache_stats_;
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
