#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>

namespace Rhp::script {

// One thing a script did that RHP knows how to take back.
// Implementations: var writes, patch handlers, Rhp::undo<F> calls, irreversible markers, schedule
// entries, subscriptions and tasks. undo() runs at most once; the ledger then destroys it.
class effect {
public:
    virtual ~effect() = default;

    // Reverses the effect. Exceptions are caught by the ledger and reported (kRevertPartial).
    virtual void undo() = 0;

    // Irreversible effects have nothing to undo and are counted in revert_report::irreversible.
    [[nodiscard]] virtual bool irreversible() const noexcept { return false; }

protected:
    effect() = default;
    effect(const effect&) = default;
    effect& operator=(const effect&) = default;
};

// Process-wide monotonic sequence shared by every ledger, so effects of different sandboxes on
// the same patch point or variable stack in a single global order. Never returns 0.
[[nodiscard]] std::uint64_t next_effect_sequence() noexcept;

struct revert_report {
    std::size_t undone = 0;       // effects reversed
    std::size_t irreversible = 0; // effects that could not be reversed (Rhp::irreversible bindings)
    std::vector<error> failures;  // undo() calls that threw
    // Requested from inside a running script: queued, applied when the outermost run returns.
    bool deferred = false;

    [[nodiscard]] bool clean() const noexcept { return failures.empty(); }
    revert_report& operator+=(revert_report&& other);
};

// Who caused an effect: a module, and the revision and request of it that were running.
// Revision and request are 0 when an effect isn't tied to one (they narrow reverts, never widen).
struct effect_owner {
    module_id module;
    revision_id revision{};
    request_id request{};

    [[nodiscard]] bool operator==(const effect_owner&) const = default;
};

// Owner-keyed undo log (the GMod hook-id / Neovim augroup / Roblox Maid pattern): every effect is
// tagged with the module that caused it, and reverting a module walks its effects newest-first.
// Single-threaded: owned by one sandbox and used on its pump thread.
class ledger {
public:
    struct entry {
        std::uint64_t seq = 0;
        module_id owner;
        revision_id revision; // 0 = not tied to a revision
        request_id request;   // 0 = not tied to a request
        std::string label; // "game.gravity", "patch combat.damage", "game.spawn"
        std::unique_ptr<effect> fx;
    };

    ledger() = default;
    ledger(const ledger&) = delete;
    ledger& operator=(const ledger&) = delete;
    ledger(ledger&& other) noexcept;
    // Undoes everything this ledger still records, then takes `other`'s effects (left empty).
    ledger& operator=(ledger&& other) noexcept;
    ~ledger(); // undoes everything still recorded

    // Appends an effect; returns its sequence number.
    std::uint64_t record(module_id owner, std::string label, std::unique_ptr<effect> fx);
    std::uint64_t record(const effect_owner& owner, std::string label, std::unique_ptr<effect> fx);

    // Undoes every effect of `owner`, newest first.
    revert_report revert(module_id owner);
    // Undoes the effects one revision of `owner` made (reload swaps revisions this way).
    revert_report revert_revision(module_id owner, revision_id revision);
    // Undoes the effects one request of `owner` made (a failed exec keeps the scratch module's others).
    revert_report revert_request(module_id owner, request_id request);
    // Undoes the single effect with this sequence number (rhp.off). Empty report if there is none.
    revert_report revert_entry(std::uint64_t seq);
    // Undoes every effect of `owner` with seq > mark, newest first.
    revert_report revert_after(module_id owner, std::uint64_t mark);
    // Undoes every effect (all owners) with seq > mark, newest first.
    revert_report revert_after(std::uint64_t mark);
    revert_report revert_all();

    [[nodiscard]] const entry* find(std::uint64_t seq) const noexcept;
    [[nodiscard]] std::size_t count(module_id owner) const noexcept;
    [[nodiscard]] std::size_t irreversible_count(module_id owner) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    // Highest seq recorded so far by any ledger (a checkpoint mark).
    [[nodiscard]] static std::uint64_t mark() noexcept;
    [[nodiscard]] std::span<const entry> entries() const noexcept { return entries_; }

private:
    template <class Pred>
    revert_report revert_if(Pred pred);

    std::vector<entry> entries_; // ascending seq
};

} // namespace Rhp::script
