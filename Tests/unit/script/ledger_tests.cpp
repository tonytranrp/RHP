#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/script/detail/var_layers.hpp>
#include <rhp/script/ledger.hpp>

using Rhp::errc;
using Rhp::module_id;
using Rhp::request_id;
using Rhp::revision_id;
using Rhp::script::effect;
using Rhp::script::effect_owner;
using Rhp::script::ledger;
using Rhp::script::revert_report;

namespace {

// Appends its id to a shared log when undone.
class logging_effect final : public effect {
public:
    logging_effect(std::vector<int>& log, int id) : log_(&log), id_(id) {}

    void undo() override { log_->push_back(id_); }

private:
    std::vector<int>* log_;
    int id_;
};

class throwing_effect final : public effect {
public:
    explicit throwing_effect(int& attempts) : attempts_(&attempts) {}

    void undo() override {
        ++*attempts_;
        throw std::runtime_error("undo exploded");
    }

private:
    int* attempts_;
};

class one_way_effect final : public effect {
public:
    explicit one_way_effect(int& undo_calls) : undo_calls_(&undo_calls) {}

    void undo() override { ++*undo_calls_; }
    [[nodiscard]] bool irreversible() const noexcept override { return true; }

private:
    int* undo_calls_;
};

std::unique_ptr<effect> logged(std::vector<int>& log, int id) {
    return std::make_unique<logging_effect>(log, id);
}

const module_id kModA{1};
const module_id kModB{2};
const module_id kModC{3};

} // namespace

// Process-wide globals for the var_layers tests; one instantiation per variable.
namespace ledger_tests_fixtures {

inline int g_layered = 0;
inline std::string g_layered_text;

} // namespace ledger_tests_fixtures

TEST_CASE("ledger records effects with increasing sequence numbers", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    REQUIRE(l.empty());
    REQUIRE(l.size() == 0);

    const std::uint64_t s1 = l.record(kModA, "a.one", logged(log, 1));
    const std::uint64_t s2 = l.record(kModB, "b.one", logged(log, 2));
    const std::uint64_t s3 = l.record(kModA, "a.two", logged(log, 3));

    REQUIRE(s1 != 0);
    REQUIRE(s1 < s2);
    REQUIRE(s2 < s3);
    REQUIRE(ledger::mark() >= s3);
    REQUIRE(l.size() == 3);
    REQUIRE_FALSE(l.empty());
    REQUIRE(l.count(kModA) == 2);
    REQUIRE(l.count(kModB) == 1);
    REQUIRE(l.count(kModC) == 0);

    const auto entries = l.entries();
    REQUIRE(entries.size() == 3);
    REQUIRE(entries[0].seq == s1);
    REQUIRE(entries[0].owner == kModA);
    REQUIRE(entries[0].label == "a.one");
    REQUIRE(entries[2].label == "a.two");
    REQUIRE(log.empty());
}

TEST_CASE("ledger reverts one owner newest first and leaves the others", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    l.record(kModA, "a1", logged(log, 1));
    l.record(kModB, "b1", logged(log, 2));
    l.record(kModA, "a2", logged(log, 3));
    l.record(kModA, "a3", logged(log, 4));

    const revert_report report = l.revert(kModA);
    REQUIRE(report.undone == 3);
    REQUIRE(report.irreversible == 0);
    REQUIRE(report.clean());
    REQUIRE(log == std::vector<int>{4, 3, 1});
    REQUIRE(l.count(kModA) == 0);
    REQUIRE(l.count(kModB) == 1);

    // Reverting again is a no-op; so is an owner with nothing recorded.
    REQUIRE(l.revert(kModA).undone == 0);
    REQUIRE(l.revert(kModC).undone == 0);
    REQUIRE(log.size() == 3);
}

TEST_CASE("ledger revert_after undoes only effects after a mark", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    l.record(kModA, "a1", logged(log, 1));
    l.record(kModB, "b1", logged(log, 2));
    const std::uint64_t mark = ledger::mark();
    l.record(kModA, "a2", logged(log, 3));
    l.record(kModB, "b2", logged(log, 4));
    l.record(kModA, "a3", logged(log, 5));

    SECTION("one owner") {
        const auto report = l.revert_after(kModA, mark);
        REQUIRE(report.undone == 2);
        REQUIRE(log == std::vector<int>{5, 3});
        REQUIRE(l.count(kModA) == 1);
        REQUIRE(l.count(kModB) == 2);
    }

    SECTION("all owners") {
        const auto report = l.revert_after(mark);
        REQUIRE(report.undone == 3);
        REQUIRE(log == std::vector<int>{5, 4, 3});
        REQUIRE(l.size() == 2);
    }

    SECTION("a mark at the newest effect undoes nothing") {
        const auto report = l.revert_after(ledger::mark());
        REQUIRE(report.undone == 0);
        REQUIRE(l.size() == 5);
    }

    SECTION("mark zero undoes everything") {
        const auto report = l.revert_after(std::uint64_t{0});
        REQUIRE(report.undone == 5);
        REQUIRE(log == std::vector<int>{5, 4, 3, 2, 1});
        REQUIRE(l.empty());
    }
}

TEST_CASE("ledger revert_all walks every owner newest first", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    for (int i = 1; i <= 6; ++i) {
        l.record(i % 2 == 0 ? kModA : kModB, "fx", logged(log, i));
    }
    const auto report = l.revert_all();
    REQUIRE(report.undone == 6);
    REQUIRE(log == std::vector<int>{6, 5, 4, 3, 2, 1});
    REQUIRE(l.empty());
    REQUIRE(l.revert_all().undone == 0);
}

TEST_CASE("ledger counts irreversible effects without undoing them", "[script][ledger]") {
    std::vector<int> log;
    int one_way_calls = 0;
    ledger l;
    l.record(kModA, "a.reversible", logged(log, 1));
    l.record(kModA, "a.explode", std::make_unique<one_way_effect>(one_way_calls));
    l.record(kModA, "a.explode", std::make_unique<one_way_effect>(one_way_calls));

    REQUIRE(l.count(kModA) == 3);
    REQUIRE(l.irreversible_count(kModA) == 2);
    REQUIRE(l.irreversible_count(kModB) == 0);

    const auto report = l.revert(kModA);
    REQUIRE(report.undone == 1);
    REQUIRE(report.irreversible == 2);
    REQUIRE(report.clean());
    REQUIRE(one_way_calls == 0);
    REQUIRE(log == std::vector<int>{1});
    REQUIRE(l.count(kModA) == 0);
}

TEST_CASE("ledger captures undo failures and keeps reverting", "[script][ledger]") {
    std::vector<int> log;
    int attempts = 0;
    ledger l;
    l.record(kModA, "a1", logged(log, 1));
    l.record(kModA, "a.broken", std::make_unique<throwing_effect>(attempts));
    l.record(kModA, "a3", logged(log, 3));

    const auto report = l.revert(kModA);
    REQUIRE(attempts == 1);
    REQUIRE(report.undone == 2);
    REQUIRE_FALSE(report.clean());
    REQUIRE(report.failures.size() == 1);
    REQUIRE(report.failures[0].code == errc::kRevertPartial);
    REQUIRE(report.failures[0].where == "a.broken");
    REQUIRE(report.failures[0].message.find("undo exploded") != std::string::npos);
    REQUIRE(log == std::vector<int>{3, 1});
    REQUIRE(l.empty());

    // The failed effect is gone: it is not retried.
    REQUIRE(l.revert(kModA).failures.empty());
    REQUIRE(attempts == 1);
}

TEST_CASE("ledger destructor undoes everything still recorded", "[script][ledger]") {
    std::vector<int> log;
    {
        ledger l;
        l.record(kModA, "a1", logged(log, 1));
        l.record(kModB, "b1", logged(log, 2));
        l.record(kModA, "a2", logged(log, 3));
        (void)l.revert(kModB);
        REQUIRE(log == std::vector<int>{2});
    }
    REQUIRE(log == std::vector<int>{2, 3, 1});
}

TEST_CASE("ledger destructor swallows undo failures", "[script][ledger]") {
    std::vector<int> log;
    int attempts = 0;
    {
        ledger l;
        l.record(kModA, "a1", logged(log, 1));
        l.record(kModA, "a.broken", std::make_unique<throwing_effect>(attempts));
    }
    REQUIRE(attempts == 1);
    REQUIRE(log == std::vector<int>{1});
}

TEST_CASE("ledger move transfers ownership of effects", "[script][ledger]") {
    std::vector<int> log;
    {
        ledger source;
        source.record(kModA, "a1", logged(log, 1));
        ledger moved{std::move(source)};
        REQUIRE(moved.size() == 1);

        ledger assigned;
        assigned = std::move(moved);
        REQUIRE(assigned.count(kModA) == 1);
        REQUIRE(log.empty());
    }
    // Undone exactly once, by the ledger that owned it last.
    REQUIRE(log == std::vector<int>{1});
}

TEST_CASE("ledger move assignment undoes the destination's own effects first", "[script][ledger]") {
    std::vector<int> log;
    {
        ledger source;
        source.record(kModA, "a1", logged(log, 1));
        ledger destination;
        destination.record(kModB, "b1", logged(log, 2));
        destination.record(kModB, "b2", logged(log, 3));

        destination = std::move(source);
        // The replaced effects were undone newest first, not silently dropped.
        REQUIRE(log == std::vector<int>{3, 2});
        REQUIRE(destination.count(kModA) == 1);
        REQUIRE(destination.count(kModB) == 0);
        REQUIRE(source.empty()); // NOLINT(bugprone-use-after-move): moved-from ledgers are empty
    }
    REQUIRE(log == std::vector<int>{3, 2, 1});
}

TEST_CASE("effect sequence is process-wide and monotonic", "[script][ledger]") {
    const std::uint64_t a = Rhp::script::next_effect_sequence();
    const std::uint64_t b = Rhp::script::next_effect_sequence();
    REQUIRE(a != 0);
    REQUIRE(b > a);
    REQUIRE(ledger::mark() >= b);

    // Two ledgers share one order.
    std::vector<int> log;
    ledger first;
    ledger second;
    const auto s1 = first.record(kModA, "x", logged(log, 1));
    const auto s2 = second.record(kModA, "x", logged(log, 2));
    const auto s3 = first.record(kModA, "x", logged(log, 3));
    REQUIRE(s1 < s2);
    REQUIRE(s2 < s3);
}

TEST_CASE("revert_report accumulates", "[script][ledger]") {
    revert_report total;
    total.undone = 1;
    revert_report more;
    more.undone = 2;
    more.irreversible = 3;
    more.failures.push_back(Rhp::make_error(errc::kRevertPartial, "x"));
    total += std::move(more);
    REQUIRE(total.undone == 3);
    REQUIRE(total.irreversible == 3);
    REQUIRE(total.failures.size() == 1);
    REQUIRE_FALSE(total.clean());
}

TEST_CASE("var_layers restores the newest write's replaced value", "[script][ledger]") {
    using layers = Rhp::script::detail::var_layers<&ledger_tests_fixtures::g_layered>;
    ledger_tests_fixtures::g_layered = 0;
    REQUIRE(layers::depth() == 0);

    // Write 1 then 2, the way set_var does: remember, then assign.
    auto first = std::make_unique<layers::write_effect>(ledger_tests_fixtures::g_layered);
    ledger_tests_fixtures::g_layered = 1;
    auto second = std::make_unique<layers::write_effect>(ledger_tests_fixtures::g_layered);
    ledger_tests_fixtures::g_layered = 2;
    REQUIRE(layers::depth() == 2);

    SECTION("newest first") {
        second->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 1);
        first->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 0);
    }

    SECTION("oldest first: the older value is handed to the newer write") {
        first->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 2);
        REQUIRE(layers::depth() == 1);
        second->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 0);
    }

    SECTION("undo twice is harmless") {
        second->undo();
        second->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 1);
        first->undo();
        REQUIRE(ledger_tests_fixtures::g_layered == 0);
    }

    REQUIRE(layers::depth() == 0);
}

TEST_CASE("var_layers through two ledgers reverts in any order", "[script][ledger]") {
    using layers = Rhp::script::detail::var_layers<&ledger_tests_fixtures::g_layered_text>;
    ledger_tests_fixtures::g_layered_text = "orig";

    ledger a;
    ledger b;
    a.record(kModA, "text", std::make_unique<layers::write_effect>(ledger_tests_fixtures::g_layered_text));
    ledger_tests_fixtures::g_layered_text = "from a";
    b.record(kModB, "text", std::make_unique<layers::write_effect>(ledger_tests_fixtures::g_layered_text));
    ledger_tests_fixtures::g_layered_text = "from b";
    a.record(kModA, "text", std::make_unique<layers::write_effect>(ledger_tests_fixtures::g_layered_text));
    ledger_tests_fixtures::g_layered_text = "from a again";
    REQUIRE(layers::depth() == 3);

    // b's write is in the middle: undoing it changes nothing visible.
    REQUIRE(b.revert(kModB).undone == 1);
    REQUIRE(ledger_tests_fixtures::g_layered_text == "from a again");
    REQUIRE(a.revert(kModA).undone == 2);
    REQUIRE(ledger_tests_fixtures::g_layered_text == "orig");
    REQUIRE(layers::depth() == 0);
}

// ---- revisions, requests and single entries ---------------------------------------------------------

TEST_CASE("ledger entries carry the owner's revision and request", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    const effect_owner owner{kModA, revision_id{2}, request_id{7}};
    const std::uint64_t full = l.record(owner, "a.full", logged(log, 1));
    const std::uint64_t bare = l.record(kModA, "a.bare", logged(log, 2));

    const ledger::entry* e = l.find(full);
    REQUIRE(e != nullptr);
    CHECK(e->seq == full);
    CHECK(e->owner == kModA);
    CHECK(e->revision == revision_id{2});
    CHECK(e->request == request_id{7});
    CHECK(e->label == "a.full");

    const ledger::entry* b = l.find(bare);
    REQUIRE(b != nullptr);
    CHECK_FALSE(b->revision.valid());
    CHECK_FALSE(b->request.valid());

    CHECK(l.find(0) == nullptr);
    CHECK(l.find(bare + 1'000'000) == nullptr);
    CHECK(effect_owner{kModA} == effect_owner{kModA, revision_id{}, request_id{}});
    CHECK_FALSE(owner == effect_owner{kModA, revision_id{2}});
}

TEST_CASE("ledger revert_revision undoes one revision of one owner", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    l.record(effect_owner{kModA, revision_id{1}}, "a.r1", logged(log, 1));
    l.record(effect_owner{kModA, revision_id{2}}, "a.r2", logged(log, 2));
    l.record(effect_owner{kModB, revision_id{2}}, "b.r2", logged(log, 3));
    l.record(effect_owner{kModA, revision_id{2}}, "a.r2", logged(log, 4));
    l.record(kModA, "a.untied", logged(log, 5));

    const auto report = l.revert_revision(kModA, revision_id{2});
    CHECK(report.undone == 2);
    CHECK(log == std::vector<int>{4, 2});
    CHECK(l.count(kModA) == 2);
    CHECK(l.count(kModB) == 1);
    CHECK(l.revert_revision(kModA, revision_id{2}).undone == 0);
    CHECK(l.revert_revision(kModC, revision_id{1}).undone == 0);

    CHECK(l.revert_revision(kModA, revision_id{1}).undone == 1);
    CHECK(log == std::vector<int>{4, 2, 1});
    CHECK(l.count(kModA) == 1); // revision 0 entries aren't any revision's
}

TEST_CASE("ledger revert_request undoes one request of one owner", "[script][ledger]") {
    std::vector<int> log;
    ledger l;
    l.record(effect_owner{kModA, revision_id{}, request_id{1}}, "a.q1", logged(log, 1));
    l.record(effect_owner{kModA, revision_id{}, request_id{2}}, "a.q2", logged(log, 2));
    l.record(effect_owner{kModB, revision_id{}, request_id{1}}, "b.q1", logged(log, 3));
    l.record(effect_owner{kModA, revision_id{}, request_id{1}}, "a.q1", logged(log, 4));

    const auto report = l.revert_request(kModA, request_id{1});
    CHECK(report.undone == 2);
    CHECK(log == std::vector<int>{4, 1});
    CHECK(l.size() == 2);
    CHECK(l.revert_request(kModA, request_id{9}).undone == 0);
}

TEST_CASE("ledger revert_entry undoes exactly one effect", "[script][ledger]") {
    std::vector<int> log;
    int one_way_calls = 0;
    ledger l;
    const std::uint64_t s1 = l.record(kModA, "a1", logged(log, 1));
    const std::uint64_t s2 = l.record(kModB, "b1", logged(log, 2));
    const std::uint64_t s3 = l.record(kModA, "a.explode", std::make_unique<one_way_effect>(one_way_calls));

    const auto report = l.revert_entry(s2);
    CHECK(report.undone == 1);
    CHECK(log == std::vector<int>{2});
    CHECK(l.find(s2) == nullptr);
    CHECK(l.find(s1) != nullptr);
    CHECK(l.size() == 2);

    const auto again = l.revert_entry(s2);
    CHECK(again.undone == 0);
    CHECK(again.irreversible == 0);
    CHECK(again.clean());

    const auto one_way = l.revert_entry(s3);
    CHECK(one_way.undone == 0);
    CHECK(one_way.irreversible == 1);
    CHECK(one_way_calls == 0);
    CHECK(l.find(s3) == nullptr);
    CHECK(l.size() == 1);
}

TEST_CASE("revert_report merges deferred with OR", "[script][ledger]") {
    revert_report total;
    CHECK_FALSE(total.deferred);
    revert_report now;
    total += std::move(now);
    CHECK_FALSE(total.deferred);
    revert_report later;
    later.deferred = true;
    total += std::move(later);
    CHECK(total.deferred);
    revert_report after;
    total += std::move(after);
    CHECK(total.deferred); // stays set
}

TEST_CASE("var_layers assign remembers and writes in one step", "[script][ledger]") {
    using layers = Rhp::script::detail::var_layers<&ledger_tests_fixtures::g_layered>;
    ledger_tests_fixtures::g_layered = 0;
    {
        auto first = layers::assign(5);
        CHECK(ledger_tests_fixtures::g_layered == 5);
        CHECK(layers::read() == 5);
        CHECK(layers::depth() == 1);
        auto second = layers::assign(9);
        CHECK(layers::read() == 9);
        first->undo(); // the older write: the newer one now remembers 0
        CHECK(ledger_tests_fixtures::g_layered == 9);
        second->undo();
        CHECK(ledger_tests_fixtures::g_layered == 0);
        CHECK(layers::depth() == 0);
    }
}
