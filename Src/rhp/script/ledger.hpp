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
// Implementations: var writes, patch handlers, Rhp::undo<F> calls, irreversible markers, and
// anything a user hook_backend records. undo() runs at most once; the ledger then destroys it.
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

    [[nodiscard]] bool clean() const noexcept { return failures.empty(); }
    revert_report& operator+=(revert_report&& other);
};

// Owner-keyed undo log (the GMod hook-id / Neovim augroup / Roblox Maid pattern): every effect is
// tagged with the module that caused it, and reverting a module walks its effects newest-first.
// Single-threaded: owned by one sandbox and used on its pump thread.
class ledger {
public:
    struct entry {
        std::uint64_t seq = 0;
        module_id owner;
        std::string label; // "game.gravity", "patch combat.damage", "game.spawn"
        std::unique_ptr<effect> fx;
    };

    ledger() = default;
    ledger(const ledger&) = delete;
    ledger& operator=(const ledger&) = delete;
    ledger(ledger&&) noexcept = default;
    ledger& operator=(ledger&&) noexcept = default;
    ~ledger(); // undoes everything still recorded

    // Appends an effect; returns its sequence number.
    std::uint64_t record(module_id owner, std::string label, std::unique_ptr<effect> fx);

    // Undoes every effect of `owner`, newest first.
    revert_report revert(module_id owner);
    // Undoes every effect of `owner` with seq > mark, newest first.
    revert_report revert_after(module_id owner, std::uint64_t mark);
    // Undoes every effect (all owners) with seq > mark, newest first.
    revert_report revert_after(std::uint64_t mark);
    revert_report revert_all();

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
