// Rhp::test end to end: Lua fixture files with known outcomes run through the runner.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/test.hpp>

namespace fs = std::filesystem;
using Rhp::test::status;

namespace runner_tests_fixture {

inline std::vector<std::string> g_spawned;
inline double g_gravity = 9.5;
inline int g_wipes = 0;

struct unit_id {
    int value = 0;
    bool operator==(const unit_id&) const = default;
};

inline std::map<int, int> g_units; // id -> x

inline int spawn(std::string kind, int count) {
    g_spawned.push_back(std::move(kind));
    return count;
}
inline void despawn(std::string, int) {
    if (!g_spawned.empty()) {
        g_spawned.pop_back();
    }
}
inline int count() {
    return static_cast<int>(g_spawned.size());
}
inline void wipe() {
    ++g_wipes;
}
inline bool unit_alive(const unit_id& id) {
    return g_units.contains(id.value);
}
inline unit_id make(int x) {
    const unit_id id{static_cast<int>(g_units.size()) + 1};
    g_units[id.value] = x;
    return id;
}
inline int move(unit_id id, int dx) {
    return g_units[id.value] += dx;
}
inline void move_back(unit_id id, int dx) {
    g_units[id.value] -= dx;
}
inline int x_of(unit_id id) {
    return g_units[id.value];
}

using arena_lib = Rhp::lib<"arena">                //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>     //
    ::fn<"count", &count>                          //
    ::fn<"wipe", &wipe, Rhp::irreversible>         //
    ::fn<"make", &make>                            //
    ::var<"gravity", &g_gravity>                   //
    ::handle<"unit", unit_id, &unit_alive>         //
    ::method<"move", &move, Rhp::undo<&move_back>> //
    ::property<"x", &x_of>;

inline int default_damage(int base, int target) {
    return base * target;
}
inline constexpr Rhp::patch_point<"rhp_test.damage", &default_damage> damage_point{};
inline constexpr Rhp::lua_event<"rhp_test.round_over", std::string> round_over{};

inline void reset() {
    g_spawned.clear();
    g_units.clear();
    g_gravity = 9.5;
    g_wipes = 0;
}

const fs::path kFixtures{RHP_TEST_FIXTURES};

Rhp::test::run_options options_for(std::vector<std::string> specs) {
    Rhp::test::run_options o;
    o.root = kFixtures;
    o.scripts.push_back(kFixtures / "scripts");
    for (const std::string& s : specs) {
        o.tests.push_back(kFixtures / "specs" / s);
    }
    o.seed = 42;
    o.limits.instructions = 20'000'000; // a runaway test stops here
    return o;
}

Rhp::test::install_fn install_arena() {
    return [](Rhp::script::sandbox& box) { return box.install<arena_lib>(); };
}

struct run {
    Rhp::test::run_result result;
    std::string text;
};

run run_specs(Rhp::test::run_options o, Rhp::test::install_fn install = install_arena()) {
    reset();
    std::ostringstream out;
    auto report = Rhp::test::make_text_reporter(out, false, true);
    Rhp::test::runner r{std::move(o), std::move(install)};
    run x{r.run(*report), ""};
    x.text = out.str();
    return x;
}

const Rhp::test::test_result* find(const Rhp::test::run_result& r, std::string_view name) {
    for (const auto& f : r.files) {
        for (const auto& t : f.tests) {
            if (t.name == name) {
                return &t;
            }
        }
    }
    return nullptr;
}

// Every test in the convention files ends its name with the outcome it must have: (ok), (fails),
// (errors), (pending) or (skipped).
std::string expected_outcome(std::string_view name) {
    for (const auto& [suffix, outcome] : {std::pair{"(ok)", "passed"}, {"(fails)", "failed"}, {"(errors)", "error"}, {"(pending)", "pending"}, {"(skipped)", "skipped"}}) {
        if (name.ends_with(suffix)) {
            return outcome;
        }
    }
    return "unmarked";
}

void check_conventions(const run& x) {
    for (const auto& f : x.result.files) {
        INFO(f.file);
        for (const auto& e : f.errors) {
            FAIL_CHECK(e.message);
        }
        for (const auto& t : f.tests) {
            INFO(t.name << "\n"
                        << t.message << "\n"
                        << t.traceback);
            CHECK(std::string{Rhp::test::to_string(t.outcome)} == expected_outcome(t.name));
        }
    }
}

} // namespace runner_tests_fixture

using namespace runner_tests_fixture;

TEST_CASE("test files report the outcomes they declare", "[test][runner]") {
    const run x = run_specs(options_for({"basics_spec.lua"}));
    INFO(x.text);
    REQUIRE(x.result.files.size() == 1);
    CHECK(x.result.files[0].errors.empty());
    const auto& c = x.result.totals;
    CHECK(c.passed == 5);
    CHECK(c.failed == 2);
    CHECK(c.errors == 1);
    CHECK(c.pending == 1);
    CHECK(c.skipped == 1);

    const auto* failed = find(x.result, "damage fails on purpose");
    REQUIRE(failed != nullptr);
    CHECK(failed->outcome == status::kFailed);
    CHECK(failed->fail_file == "specs/basics_spec.lua");
    CHECK(failed->fail_line == 14);
    CHECK(failed->message.find("Expected objects to be equal.") != std::string::npos);
    CHECK(failed->message.find("(number) 7") != std::string::npos);
    CHECK(failed->message.find("(number) 8") != std::string::npos);
    REQUIRE(failed->expected.has_value());
    CHECK(*failed->expected == "8");
    CHECK(*failed->actual == "7");

    const auto* deep = find(x.result, "damage fails a deep comparison");
    REQUIRE(deep != nullptr);
    CHECK(deep->fail_line == 18);
    CHECK(deep->message.find("First difference at b.c: 3 instead of 2") != std::string::npos);

    const auto* errored = find(x.result, "damage errors on purpose");
    REQUIRE(errored != nullptr);
    CHECK(errored->outcome == status::kError);
    CHECK(errored->fail_line == 23);
    CHECK(errored->message.find("attempt to index") != std::string::npos);

    const auto* tagged = find(x.result, "handles tables and strings #fast");
    REQUIRE(tagged != nullptr);
    CHECK(tagged->tags == std::vector<std::string>{"fast"});
    CHECK(tagged->assertions == 7);
    CHECK(tagged->cost.instructions > 0);
}

TEST_CASE("assert behaves like luassert", "[test][assert]") {
    const run x = run_specs(options_for({"assert_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* custom = find(x.result, "assert a message argument (fails)");
    REQUIRE(custom != nullptr);
    CHECK(custom->message.starts_with("the custom message"));
    const auto* table_error = find(x.result, "assert an error with a table value (errors)");
    REQUIRE(table_error != nullptr);
    CHECK(table_error->message == "error object: {code = 9}");
}

TEST_CASE("expect behaves like Jest", "[test][expect]") {
    const run x = run_specs(options_for({"expect_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* diff = find(x.result, "expect equal shows the first difference (fails)");
    REQUIRE(diff != nullptr);
    CHECK(diff->message.find("first difference at a[2]: 2 instead of 3") != std::string::npos);
    CHECK(diff->expected.has_value());
    const auto* unknown = find(x.result, "expect an unknown matcher (errors)");
    REQUIRE(unknown != nullptr);
    CHECK(unknown->message.find("no matcher 'be_purple'") != std::string::npos);
}

TEST_CASE("spies stubs and mocks reach libs handles and modules", "[test][spy]") {
    const run x = run_specs(options_for({"spy_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    CHECK(g_spawned.empty());
    CHECK(g_gravity == 9.5);
}

TEST_CASE("the fake clock drives timers frames events and points", "[test][clock]") {
    const run x = run_specs(options_for({"clock_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* loop = find(x.result, "clock an endless timer loop is reported by run_all (fails)");
    REQUIRE(loop != nullptr);
    CHECK(loop->message.find("still running after 5 steps") != std::string::npos);
    CHECK(g_spawned.empty());
}

TEST_CASE("measures budgets and leak checks", "[test][measure]") {
    const run x = run_specs(options_for({"measure_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* measured = find(x.result, "measure measure counts instructions and memory (ok)");
    REQUIRE(measured != nullptr);
    REQUIRE(measured->measures.size() == 4);
    CHECK(measured->measures[0].name == "sum 10");
    CHECK(measured->measures[1].instructions > measured->measures[0].instructions * 20);
    const auto* benched = find(x.result, "measure bench reports statistics (ok)");
    REQUIRE(benched != nullptr);
    REQUIRE(benched->benches.size() == 1);
    CHECK(benched->benches[0].runs == 10);
    CHECK(benched->benches[0].instructions.stddev == 0);
    const auto* over = find(x.result, "measure over the instruction budget (fails)");
    REQUIRE(over != nullptr);
    CHECK(over->message.find("over budget: instructions") != std::string::npos);
    const auto* global = find(x.result, "measure a global left behind is removed (ok)");
    REQUIRE(global != nullptr);
    REQUIRE(global->notes.size() == 1);
    CHECK(global->notes[0].find("leaked_global") != std::string::npos);
    const auto* wiped = find(x.result, "measure an irreversible effect with expect_undone (errors)");
    REQUIRE(wiped != nullptr);
    CHECK(wiped->message.find("irreversible") != std::string::npos);
    const auto* runaway = find(x.result, "measure a limit stops a runaway test (errors)");
    REQUIRE(runaway != nullptr);
    CHECK(runaway->message.find("instruction") != std::string::npos);
    CHECK(runaway->traceback.find("rhp.test/") == std::string::npos);
}

// Runs <temp>/rhp_probe_spec.lua and prints the text report: a debugging aid, hidden.
TEST_CASE("probe", "[.probe]") {
    const fs::path spec = fs::temp_directory_path() / "rhp_probe_spec.lua";
    REQUIRE(fs::exists(spec));
    Rhp::test::run_options o = options_for({});
    o.tests.push_back(spec);
    o.verbose = true;
    const run x = run_specs(o);
    std::puts(x.text.c_str());
}

TEST_CASE("the DSL nests hooks setup each pending skip and tags", "[test][dsl]") {
    const run x = run_specs(options_for({"dsl_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    CHECK(find(x.result, "each 2 plus 3 is 5 (ok)") != nullptr);
    CHECK(find(x.result, "each elf has hp (ok)") != nullptr);
    CHECK(find(x.result, "each case 2 is b (ok)") != nullptr);
    CHECK(find(x.result, "each block 20 gets its value (ok)") != nullptr);
    const auto* tagged = find(x.result, "tags a #slow #net test (ok)");
    REQUIRE(tagged != nullptr);
    CHECK(tagged->tags == std::vector<std::string>{"slow", "net"});
    const auto* pending = find(x.result, "outer pending inside a body (pending)");
    REQUIRE(pending != nullptr);
    CHECK(pending->message == "not written yet");
    const auto* setup = find(x.result, "a failing setup this one too (errors)");
    REQUIRE(setup != nullptr);
    CHECK(setup->message.find("setup of 'a failing setup' failed") != std::string::npos);
    CHECK(setup->message.find("setup broke") != std::string::npos);
}

TEST_CASE("only selects tests within a file", "[test][dsl]") {
    const run x = run_specs(options_for({"only_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    CHECK(x.result.totals.passed == 2);
    CHECK(x.result.totals.skipped == 2);
}

TEST_CASE("file errors are reported with their place", "[test][dsl]") {
    const run x = run_specs(options_for({"broken_describe_spec.lua", "syntax_error_spec.lua"}));
    INFO(x.text);
    REQUIRE(x.result.files.size() == 2);
    const auto& broken = x.result.files[0];
    REQUIRE(broken.errors.size() == 1);
    CHECK(broken.errors[0].message.find("describe 'broken' failed") != std::string::npos);
    CHECK(broken.errors[0].line == 5);
    REQUIRE(broken.tests.size() == 1);
    CHECK(broken.tests[0].outcome == status::kPassed);
    const auto& syntax = x.result.files[1];
    REQUIRE(syntax.errors.size() == 1);
    CHECK(syntax.errors[0].message.find("syntax_error_spec.lua:2") != std::string::npos);
    CHECK(syntax.tests.empty());
    CHECK(x.result.totals.file_errors == 2);
    CHECK_FALSE(x.result.totals.ok());
}

namespace runner_tests_fixture {

// A copy of the fixture scripts and some specs in a fresh folder (snapshots and corpora are written
// next to the specs).
struct temp_tree {
    fs::path root;

    explicit temp_tree(std::string_view name, std::vector<std::string> specs) {
        root = fs::temp_directory_path() / std::format("rhp_test_{}_{}", name, std::chrono::steady_clock::now().time_since_epoch().count());
        fs::create_directories(root / "specs");
        fs::copy(kFixtures / "scripts", root / "scripts", fs::copy_options::recursive);
        for (const std::string& s : specs) {
            fs::copy_file(kFixtures / "specs" / s, root / "specs" / s);
        }
    }
    ~temp_tree() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    temp_tree(const temp_tree&) = delete;
    temp_tree& operator=(const temp_tree&) = delete;

    [[nodiscard]] Rhp::test::run_options options(std::vector<std::string> specs) const {
        Rhp::test::run_options o;
        o.root = root;
        o.scripts.push_back(root / "scripts");
        for (const std::string& s : specs) {
            o.tests.push_back(root / "specs" / s);
        }
        o.seed = 42;
        o.limits.instructions = 20'000'000;
        return o;
    }

    void replace(const std::string& spec, std::string_view from, std::string_view to) const {
        const fs::path p = root / "specs" / spec;
        std::string text = read_file(p);
        const std::size_t at = text.find(from);
        REQUIRE(at != std::string::npos);
        text.replace(at, from.size(), to);
        write_file(p, text);
    }

    static std::string read_file(const fs::path& p) {
        std::ifstream in{p, std::ios::binary};
        return std::string{std::istreambuf_iterator<char>{in}, {}};
    }
    static void write_file(const fs::path& p, std::string_view text) {
        std::ofstream out{p, std::ios::binary | std::ios::trunc};
        out << text;
    }
};

status outcome_of(const run& x, std::string_view name) {
    const auto* t = find(x.result, name);
    REQUIRE(t != nullptr);
    return t->outcome;
}

} // namespace runner_tests_fixture

TEST_CASE("snapshots are stored matched updated and refused in ci", "[test][snapshot]") {
    const temp_tree tree{"snap", {"snapshot_spec.lua"}};
    tree.replace("snapshot_spec.lua", "VALUE)", "{ 1, 2 })");
    const fs::path stored = tree.root / "specs" / "__snapshots__" / "snapshot_spec.snap.lua";

    run x = run_specs(tree.options({"snapshot_spec.lua"}));
    INFO(x.text);
    CHECK(x.result.totals.passed == 2);
    REQUIRE(fs::exists(stored));
    const std::string first = temp_tree::read_file(stored);
    CHECK(first.find("[\"snapshot a table (ok) 1\"] = [=[") != std::string::npos);
    CHECK(first.find("[\"snapshot named snapshots and expect (ok) damage\"] = [[7]],") != std::string::npos);
    CHECK(first.find("snapshot named snapshots and expect (ok) damage") != std::string::npos);

    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 2);
    CHECK(temp_tree::read_file(stored) == first);

    tree.replace("snapshot_spec.lua", "{ 1, 2 })", "{ 1, 3 })");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    const auto* changed = find(x.result, "snapshot named snapshots and expect (ok)");
    REQUIRE(changed != nullptr);
    CHECK(changed->outcome == status::kFailed);
    CHECK(changed->message.find("doesn't match") != std::string::npos);
    CHECK(changed->expected.has_value());
    CHECK(changed->actual.has_value());

    Rhp::test::run_options update = tree.options({"snapshot_spec.lua"});
    update.update_snapshots = true;
    x = run_specs(update);
    CHECK(x.result.totals.passed == 2);
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 2);

    // A renamed test leaves its snapshot behind: reported as obsolete, removed by an update.
    tree.replace("snapshot_spec.lua", "it(\"a table (ok)\"", "it(\"a renamed table (ok)\"");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 2);
    bool obsolete = false;
    for (const std::string& n : x.result.notes) {
        obsolete = obsolete || n.find("obsolete") != std::string::npos;
    }
    CHECK(obsolete);

    // An unreadable file fails its tests and is left alone.
    const std::string good = temp_tree::read_file(stored);
    temp_tree::write_file(stored, "return {");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.failed == 2);
    CHECK(find(x.result, "snapshot named snapshots and expect (ok)")->message.find("isn't a snapshot file") != std::string::npos);
    CHECK(temp_tree::read_file(stored) == "return {");
    temp_tree::write_file(stored, good);

    fs::remove(stored);
    Rhp::test::run_options ci = tree.options({"snapshot_spec.lua"});
    ci.ci = true;
    x = run_specs(ci);
    CHECK(x.result.totals.failed == 2);
    CHECK_FALSE(fs::exists(stored));
    const auto* refused = find(x.result, "snapshot named snapshots and expect (ok)");
    REQUIRE(refused != nullptr);
    CHECK(refused->message.find("--ci refuses") != std::string::npos);
}

TEST_CASE("properties shrink failures and reproduce from the seed", "[test][property]") {
    const run x = run_specs(options_for({"property_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* small = find(x.result, "property a failing property shrinks to the smallest case (fails)");
    REQUIRE(small != nullptr);
    CHECK(small->message.find("Counterexample: (50)") != std::string::npos);
    const auto* list = find(x.result, "property a failing list property shrinks the list (fails)");
    REQUIRE(list != nullptr);
    CHECK(list->message.find("the property returned false") != std::string::npos);

    const run again = run_specs(options_for({"property_spec.lua"}));
    const auto* list_again = find(again.result, "property a failing list property shrinks the list (fails)");
    REQUIRE(list_again != nullptr);
    CHECK(list_again->message == list->message);
}

TEST_CASE("fuzzing finds shrinks and keeps crashes", "[test][fuzz]") {
    const temp_tree tree{"fuzz", {"fuzz_spec.lua"}};
    run x = run_specs(tree.options({"fuzz_spec.lua"}));
    INFO(x.text);
    check_conventions(x);
    const auto* crash = find(x.result, "fuzz finds the crash (fails)");
    REQUIRE(crash != nullptr);
    CHECK(crash->message.find("Fuzzing found a failure") != std::string::npos);
    const std::size_t at = crash->message.find("Input: ('");
    REQUIRE(at != std::string::npos);
    CHECK(crash->message.substr(at + 12, 2) == "')"); // shrunk to 3 characters
    const fs::path corpus = tree.root / "specs" / "__fuzz__" / "fuzz_spec" / "fuzz_finds_the_crash__fails_";
    REQUIRE(fs::exists(corpus));
    CHECK(std::distance(fs::directory_iterator{corpus}, fs::directory_iterator{}) == 1);

    // The saved crash runs first next time, whatever the seed.
    Rhp::test::run_options other = tree.options({"fuzz_spec.lua"});
    other.seed = 7;
    x = run_specs(other);
    CHECK(outcome_of(x, "fuzz finds the crash (fails)") == status::kFailed);
    CHECK(std::distance(fs::directory_iterator{corpus}, fs::directory_iterator{}) == 1);
}

TEST_CASE("isolation per file keeps module state and per test starts fresh", "[test][isolation]") {
    Rhp::test::run_options o = options_for({"isolation_spec.lua"});
    run x = run_specs(o);
    INFO(x.text);
    CHECK(outcome_of(x, "second reads the module state") == status::kPassed);
    o.share = Rhp::test::isolation::kTest;
    x = run_specs(o);
    CHECK(outcome_of(x, "second reads the module state") == status::kFailed);
    CHECK(g_spawned.empty());
}

namespace runner_tests_fixture {

std::vector<std::string> names_of(const run& x) {
    std::vector<std::string> out;
    for (const auto& f : x.result.files) {
        for (const auto& t : f.tests) {
            if (t.outcome != status::kSkipped) {
                out.push_back(t.name);
            }
        }
    }
    return out;
}

} // namespace runner_tests_fixture

TEST_CASE("tests are selected by name pattern and tag", "[test][select]") {
    using v = std::vector<std::string>;
    Rhp::test::run_options o = options_for({"select_spec.lua"});
    o.filters = {"alpha"};
    CHECK(names_of(run_specs(o)) == v{"alpha one #fast", "alpha two #slow", "alpha three #fast #net"});
    o.filters = {"/^beta (four|six)$/"};
    CHECK(names_of(run_specs(o)) == v{"beta four", "beta six"});
    o.filters = {};
    o.filters_out = {"beta"};
    CHECK(names_of(run_specs(o)) == v{"alpha one #fast", "alpha two #slow", "alpha three #fast #net"});
    o.filters_out = {};
    o.tags = {"fast"};
    CHECK(names_of(run_specs(o)) == v{"alpha one #fast", "alpha three #fast #net"});
    o.exclude_tags = {"net"};
    CHECK(names_of(run_specs(o)) == v{"alpha one #fast"});
}

TEST_CASE("shuffle repeat and fail fast", "[test][select]") {
    using v = std::vector<std::string>;
    const v declared{"alpha one #fast", "alpha two #slow", "alpha three #fast #net", "beta four", "beta five fails", "beta six"};
    Rhp::test::run_options o = options_for({"select_spec.lua"});
    o.shuffle = true;
    const v first = names_of(run_specs(o));
    CHECK(first != declared);
    CHECK(std::is_permutation(first.begin(), first.end(), declared.begin(), declared.end()));
    CHECK(names_of(run_specs(o)) == first); // the same seed, the same order
    o.seed = 43;
    CHECK(names_of(run_specs(o)) != first);

    o = options_for({"select_spec.lua"});
    o.repeat = 3;
    const run repeated = run_specs(o);
    CHECK(repeated.result.files[0].tests.size() == 18);
    CHECK(repeated.result.files[0].tests.back().repeat == 2);
    CHECK(repeated.result.totals.failed == 0);
    CHECK(repeated.result.totals.errors == 3);

    o = options_for({"select_spec.lua", "basics_spec.lua"});
    o.fail_fast = true;
    const run fast = run_specs(o);
    CHECK(names_of(fast) == v{"alpha one #fast", "alpha two #slow", "alpha three #fast #net", "beta four", "beta five fails"});
}

TEST_CASE("tests that never end are stopped", "[test][timeout]") {
    Rhp::test::run_options o = options_for({"timeout_spec.lua"});
    o.limits.instructions = 0;
    o.timeout = std::chrono::milliseconds{300};
    o.max_frames = 500;
    const auto started = std::chrono::steady_clock::now();
    const run x = run_specs(o);
    INFO(x.text);
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds{10});
    const auto* spinner = find(x.result, "spins forever");
    REQUIRE(spinner != nullptr);
    CHECK(spinner->outcome == status::kError);
    CHECK(spinner->message.find("time") != std::string::npos);
    CHECK(outcome_of(x, "still runs after the spinner") == status::kPassed);
    const auto* waiter = find(x.result, "waits on frames forever");
    REQUIRE(waiter != nullptr);
    CHECK(waiter->outcome == status::kError);
    CHECK(waiter->message.find("500 frames") != std::string::npos);
}
