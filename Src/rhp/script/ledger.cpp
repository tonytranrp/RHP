#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <format>
#include <iterator>
#include <utility>

#include <rhp/script/ledger.hpp>

namespace Rhp::script {

namespace {

std::atomic<std::uint64_t>& sequence() {
    static std::atomic<std::uint64_t> seq{0};
    return seq;
}

} // namespace

std::uint64_t next_effect_sequence() noexcept {
    return sequence().fetch_add(1, std::memory_order_relaxed) + 1;
}

std::uint64_t ledger::mark() noexcept {
    return sequence().load(std::memory_order_relaxed);
}

revert_report& revert_report::operator+=(revert_report&& other) {
    undone += other.undone;
    irreversible += other.irreversible;
    failures.insert(failures.end(), std::make_move_iterator(other.failures.begin()), std::make_move_iterator(other.failures.end()));
    deferred = deferred || other.deferred;
    return *this;
}

ledger::~ledger() {
    (void)revert_all();
}

std::uint64_t ledger::record(module_id owner, std::string label, std::unique_ptr<effect> fx) {
    return record(effect_owner{owner}, std::move(label), std::move(fx));
}

std::uint64_t ledger::record(const effect_owner& owner, std::string label, std::unique_ptr<effect> fx) {
    const std::uint64_t seq = next_effect_sequence();
    entries_.push_back(entry{seq, owner.module, owner.revision, owner.request, std::move(label), std::move(fx)});
    return seq;
}

template <class Pred>
revert_report ledger::revert_if(Pred pred) {
    // Detach the matching entries first, so an undo that records new effects (or reverts
    // re-entrantly) never sees a half-walked vector.
    std::vector<entry> doomed;
    auto keep = entries_.begin();
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (pred(*it)) {
            doomed.push_back(std::move(*it));
        } else {
            if (keep != it) {
                *keep = std::move(*it);
            }
            ++keep;
        }
    }
    entries_.erase(keep, entries_.end());

    revert_report report;
    for (auto it = doomed.rbegin(); it != doomed.rend(); ++it) {
        if (it->fx == nullptr) {
            continue;
        }
        if (it->fx->irreversible()) {
            ++report.irreversible;
            continue;
        }
        try {
            it->fx->undo();
            ++report.undone;
        } catch (const std::exception& e) {
            report.failures.push_back(make_error(errc::kRevertPartial, std::format("undo failed: {}", e.what()), it->label));
        } catch (...) {
            report.failures.push_back(make_error(errc::kRevertPartial, "undo failed with an unknown exception", it->label));
        }
        it->fx.reset();
    }
    return report;
}

revert_report ledger::revert(module_id owner) {
    return revert_if([owner](const entry& e) { return e.owner == owner; });
}

revert_report ledger::revert_revision(module_id owner, revision_id revision) {
    return revert_if([owner, revision](const entry& e) { return e.owner == owner && e.revision == revision; });
}

revert_report ledger::revert_request(module_id owner, request_id request) {
    return revert_if([owner, request](const entry& e) { return e.owner == owner && e.request == request; });
}

revert_report ledger::revert_entry(std::uint64_t seq) {
    return revert_if([seq](const entry& e) { return e.seq == seq; });
}

revert_report ledger::revert_after(module_id owner, std::uint64_t mark) {
    return revert_if([owner, mark](const entry& e) { return e.owner == owner && e.seq > mark; });
}

revert_report ledger::revert_after(std::uint64_t mark) {
    return revert_if([mark](const entry& e) { return e.seq > mark; });
}

revert_report ledger::revert_all() {
    return revert_if([](const entry&) { return true; });
}

const ledger::entry* ledger::find(std::uint64_t seq) const noexcept {
    const auto it = std::ranges::lower_bound(entries_, seq, {}, &entry::seq);
    return it != entries_.end() && it->seq == seq ? &*it : nullptr;
}

std::size_t ledger::count(module_id owner) const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(entries_, [owner](const entry& e) { return e.owner == owner; }));
}

std::size_t ledger::irreversible_count(module_id owner) const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(entries_, [owner](const entry& e) {
        return e.owner == owner && e.fx != nullptr && e.fx->irreversible();
    }));
}

} // namespace Rhp::script
