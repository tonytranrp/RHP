// Rhp::test end to end: Lua fixture files with known outcomes run through the runner.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <regex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "embedded_fixtures.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/json.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/test.hpp>
#include <rhp/utils/scope_guard.hpp>

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

// The fixture folder: the source tree's, or (on a device that can't read it) the embedded copy
// written to a temporary folder.
fs::path fixtures_root() {
    const fs::path source{RHP_TEST_FIXTURES};
    std::error_code ec;
    if (fs::exists(source / "specs" / "basics_spec.lua", ec)) {
        return source;
    }
    const fs::path base = fs::temp_directory_path() / std::format("rhp_test_fixtures_{}", std::chrono::steady_clock::now().time_since_epoch().count());
    for (const auto& f : rhp_test_fixtures::fixture_files()) {
        const fs::path path = base / fs::path{std::string{f.name}};
        fs::create_directories(path.parent_path(), ec);
        std::ofstream{path, std::ios::binary} << f.text;
    }
    return base / "fixtures";
}

// Computed on first use: the embedded table is initialized dynamically, so not before main().
const fs::path& fixtures_dir() {
    static const fs::path dir = fixtures_root();
    return dir;
}

Rhp::test::run_options options_for(std::vector<std::string> specs) {
    Rhp::test::run_options o;
    o.root = fixtures_dir();
    o.scripts.push_back(fixtures_dir() / "scripts");
    for (const std::string& s : specs) {
        o.tests.push_back(fixtures_dir() / "specs" / s);
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
    auto report = Rhp::test::make_text_reporter(out, false, true, o.coverage);
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
    const auto* peak = find(x.result, "measure measuring something small keeps the test's own peak (fails)");
    REQUIRE(peak != nullptr);
    CHECK(peak->message.find("over budget: memory") != std::string::npos);
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
        fs::copy(fixtures_dir() / "scripts", root / "scripts", fs::copy_options::recursive);
        for (const std::string& s : specs) {
            fs::copy_file(fixtures_dir() / "specs" / s, root / "specs" / s);
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
    CHECK(x.result.totals.passed == 3);
    REQUIRE(fs::exists(stored));
    const std::string first = temp_tree::read_file(stored);
    CHECK(first.find("[\"snapshot a table (ok) 1\"] = [=[") != std::string::npos);
    CHECK(first.find("[\"snapshot named snapshots and expect (ok) damage\"] = [[7]],") != std::string::npos);
    CHECK(first.find("snapshot named snapshots and expect (ok) damage") != std::string::npos);

    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 3);
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
    CHECK(x.result.totals.passed == 3);
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 3);

    // A renamed test leaves its snapshot behind: reported as obsolete, removed by an update.
    tree.replace("snapshot_spec.lua", "it(\"a table (ok)\"", "it(\"a renamed table (ok)\"");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 3);
    bool obsolete = false;
    for (const std::string& n : x.result.notes) {
        obsolete = obsolete || n.find("obsolete") != std::string::npos;
    }
    CHECK(obsolete);

    // An unreadable file fails its tests and is left alone.
    const std::string good = temp_tree::read_file(stored);
    temp_tree::write_file(stored, "return {");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.failed == 3);
    CHECK(find(x.result, "snapshot named snapshots and expect (ok)")->message.find("isn't a snapshot file") != std::string::npos);
    CHECK(temp_tree::read_file(stored) == "return {");
    temp_tree::write_file(stored, good);

    fs::remove(stored);
    Rhp::test::run_options ci = tree.options({"snapshot_spec.lua"});
    ci.ci = true;
    x = run_specs(ci);
    CHECK(x.result.totals.failed == 3);
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
    const auto* negative = find(x.result, "property a failing negative property shrinks and ends (fails)");
    REQUIRE(negative != nullptr);
    CHECK(negative->message.find("Counterexample: (-5)") != std::string::npos);
    const auto* either = find(x.result, "property one_of shrinks values of either kind (fails)");
    REQUIRE(either != nullptr);
    CHECK(either->message.find("Counterexample: ('x')") != std::string::npos);
    const auto* optional = find(x.result, "property optional shrinks to nil (fails)");
    REQUIRE(optional != nullptr);
    CHECK(optional->message.find("Counterexample: (nil)") != std::string::npos);

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
    const auto* any = find(x.result, "fuzz finds a crash with the default generator (fails)");
    REQUIRE(any != nullptr);
    CHECK(any->message.find("Fuzzing found a failure") != std::string::npos);
    CHECK(any->message.find("too long") != std::string::npos);
    CHECK(any->message.find("attempt to") == std::string::npos); // shrinking gen.any() works
    fs::path corpus;
    std::size_t corpora = 0;
    for (const auto& dir : fs::directory_iterator{tree.root / "specs" / "__fuzz__" / "fuzz_spec"}) {
        ++corpora;
        if (dir.path().filename().string().starts_with("fuzz_finds_the_crash__fails_")) {
            corpus = dir.path();
        }
    }
    CHECK(corpora == 2); // both crashes saved, each in its own folder
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

namespace runner_tests_fixture {

const Rhp::test::file_coverage* coverage_of(const run& x, std::string_view file) {
    for (const auto& f : x.result.coverage) {
        if (f.file == file) {
            return &f;
        }
    }
    return nullptr;
}

std::uint64_t hits_at(const Rhp::test::file_coverage& f, std::uint32_t line) {
    for (std::size_t i = 0; i < f.lines.size(); ++i) {
        if (f.lines[i] == line) {
            return f.hits[i];
        }
    }
    return (std::numeric_limits<std::uint64_t>::max)(); // not an executable line
}

constexpr std::uint64_t kNotExecutable = (std::numeric_limits<std::uint64_t>::max)();

} // namespace runner_tests_fixture

TEST_CASE("coverage counts lines of the scripts and honours exclusions", "[test][coverage]") {
    const temp_tree tree{"cov", {"coverage_spec.lua"}};
    Rhp::test::run_options o = tree.options({"coverage_spec.lua"});
    o.coverage = {{Rhp::test::coverage_kind::kSummary, {}}};
    for (const auto share : {Rhp::test::isolation::kFile, Rhp::test::isolation::kTest}) {
        o.share = share;
        const run x = run_specs(o);
        INFO(x.text);
        CHECK(x.result.totals.passed == 2);
        const auto* combat = coverage_of(x, "scripts/game/combat.lua");
        REQUIRE(combat != nullptr);
        CHECK(hits_at(*combat, 1) == kNotExecutable); // a comment
        CHECK(hits_at(*combat, 3) == kNotExecutable); // blank
        CHECK(hits_at(*combat, 37) == 3);             // the loop body of big_list(3)
        CHECK(hits_at(*combat, 10) == 1);             // damage(5, 1)
        CHECK(hits_at(*combat, 8) == 0);              // armor >= base never
        CHECK(hits_at(*combat, 26) == 0);             // stop() never runs
        CHECK(hits_at(*combat, 45) == 200000);
        CHECK(hits_at(*combat, 2) == (share == Rhp::test::isolation::kFile ? 1 : 2)); // loaded once per sandbox
        const auto* util = coverage_of(x, "scripts/game/util.lua");
        REQUIRE(util != nullptr);
        CHECK(hits_at(*util, 5) == 1);
        CHECK(hits_at(*util, 10) == kNotExecutable); // rhp: coverage off
        CHECK(hits_at(*util, 16) == kNotExecutable); // luacov: disable
        CHECK(hits_at(*util, 21) == 0);
        CHECK(coverage_of(x, "specs/coverage_spec.lua") == nullptr);
        CHECK(x.text.find("scripts/game/combat.lua") != std::string::npos); // the summary table

        const std::string lcov = Rhp::test::lcov_text(x.result.coverage);
        CHECK(lcov.find("SF:scripts/game/combat.lua\n") != std::string::npos);
        CHECK(lcov.find("DA:37,3\n") != std::string::npos);
        CHECK(lcov.find("end_of_record") != std::string::npos);
        const std::string cobertura = Rhp::test::cobertura_text(x.result.coverage, tree.root.generic_string());
        CHECK(cobertura.find("<coverage line-rate=") != std::string::npos);
        CHECK(cobertura.find("filename=\"scripts/game/combat.lua\"") != std::string::npos);
        CHECK(cobertura.find("<line number=\"37\" hits=\"3\" branch=\"false\"/>") != std::string::npos);
    }

    o.share = Rhp::test::isolation::kFile;
    o.coverage_tests = true;
    const run with_tests = run_specs(o);
    const auto* spec = coverage_of(with_tests, "specs/coverage_spec.lua");
    REQUIRE(spec != nullptr);
    CHECK(hits_at(*spec, 5) == 1);
}

TEST_CASE("the profiler samples every test", "[test][profile]") {
    const temp_tree tree{"prof", {"coverage_spec.lua"}};
    Rhp::test::run_options o = tree.options({"coverage_spec.lua"});
    o.profile = true;
    o.profile_interval = 100;
    const run x = run_specs(o);
    INFO(x.text);
    REQUIRE_FALSE(x.result.profile.empty());
    const auto* sum = find(x.result, "spends time in sum");
    REQUIRE(sum != nullptr);
    REQUIRE_FALSE(sum->profile.empty());
    bool in_sum = false;
    for (const auto& s : sum->profile) {
        in_sum = in_sum || s.stack.find("sum") != std::string::npos;
    }
    CHECK(in_sum);
    const std::string folded = Rhp::test::folded_text(x.result.profile);
    CHECK(folded.find("sum") != std::string::npos);
    CHECK(folded.back() == '\n');
}

namespace runner_tests_fixture {

// Report text without what changes between runs: durations, timestamps, table addresses.
std::string normalized(std::string text) {
    static const std::regex ms_text{R"(\b\d+(\.\d+)? (ms|s)\b)"};
    static const std::regex ms_json{R"#("(ms|time_ms|wall_ms|duration_ms)":-?[0-9.e+-]+)#"};
    static const std::regex xml_time{R"#(\b(time|timestamp)="[^"]*")#"};
    static const std::regex tap_time{R"(duration_ms: [0-9.]+)"};
    static const std::regex address{R"((table|function|userdata|thread): (0x)?[0-9A-Fa-f]+)"};
    static const std::regex sizes{R"(peak [0-9.]+ (B|KiB|MiB), [0-9]+ alloc)"};
    static const std::regex json_costs{R"#("(peak|bytes|allocations|retained|frames|instructions)":-?[0-9]+)#"};
    static const std::regex ranking{R"(^ +[0-9][0-9.]*( (B|KiB|MiB))?  )"}; // "most instructions" lines
    text = std::regex_replace(text, ms_text, "<time>");
    text = std::regex_replace(text, ms_json, "\"$1\":0");
    text = std::regex_replace(text, xml_time, "$1=\"0\"");
    text = std::regex_replace(text, tap_time, "duration_ms: 0");
    text = std::regex_replace(text, address, "$1: <addr>");
    text = std::regex_replace(text, sizes, "<memory>");
    text = std::regex_replace(text, json_costs, "\"$1\":0");
    std::string out;
    std::istringstream lines{text};
    for (std::string line; std::getline(lines, line);) {
        if (std::regex_search(line, ranking)) {
            continue; // the "most instructions / memory" rows: their order follows the figures
        }
        out += line + "\n";
    }
    return out;
}

void check_golden(std::string_view name, const std::string& actual) {
    const fs::path golden = fixtures_dir().parent_path() / "golden" / name;
    const std::string text = normalized(actual);
    std::string expected = fs::exists(golden) ? temp_tree::read_file(golden) : std::string{};
    std::erase(expected, '\r'); // a checkout with CRLF line ends
    if (text != expected) {
        temp_tree::write_file(fs::path{golden} += ".actual", text); // review it, then rename it over the golden file
    }
    INFO("golden " << golden.generic_string());
    CHECK(text == expected);
}

std::string report_with(Rhp::test::report_kind kind, Rhp::test::run_options o) {
    std::ostringstream out;
    std::unique_ptr<Rhp::test::reporter> r;
    switch (kind) {
    case Rhp::test::report_kind::kText: r = Rhp::test::make_text_reporter(out, false, false); break;
    case Rhp::test::report_kind::kTap: r = Rhp::test::make_tap_reporter(out); break;
    case Rhp::test::report_kind::kJunit: r = Rhp::test::make_junit_reporter(out); break;
    case Rhp::test::report_kind::kJson: r = Rhp::test::make_json_reporter(out); break;
    case Rhp::test::report_kind::kGithub: r = Rhp::test::make_github_reporter(out); break;
    }
    reset();
    Rhp::test::runner runner{std::move(o), install_arena()};
    (void)runner.run(*r);
    return out.str();
}

} // namespace runner_tests_fixture

TEST_CASE("reporters write the formats they promise", "[test][reporter]") {
    const Rhp::test::run_options o = options_for({"basics_spec.lua", "broken_describe_spec.lua"});
    check_golden("basics.txt", report_with(Rhp::test::report_kind::kText, o));
    check_golden("basics.tap", report_with(Rhp::test::report_kind::kTap, o));
    check_golden("basics.junit.xml", report_with(Rhp::test::report_kind::kJunit, o));
    check_golden("basics.jsonl", report_with(Rhp::test::report_kind::kJson, o));
    check_golden("basics.github", report_with(Rhp::test::report_kind::kGithub, o));
}

TEST_CASE("xml_escape keeps well-formed UTF-8 and replaces every other byte", "[test][reporter]") {
    using Rhp::test::xml_escape;
    const std::string r = "\xEF\xBF\xBD"; // U+FFFD
    CHECK(xml_escape("a<b & \"c\"") == "a&lt;b &amp; &quot;c&quot;");
    CHECK(xml_escape("\xC3\xA9") == "\xC3\xA9");                 // U+00E9
    CHECK(xml_escape("\xE2\x82\xAC") == "\xE2\x82\xAC");         // U+20AC
    CHECK(xml_escape("\xF0\x9F\x98\x80") == "\xF0\x9F\x98\x80"); // U+1F600
    CHECK(xml_escape("\xF4\x8F\xBF\xBF") == "\xF4\x8F\xBF\xBF"); // U+10FFFF
    CHECK(xml_escape("\xF4\x90\x80\x80") == r + r + r + r);      // above U+10FFFF
    CHECK(xml_escape("\xC0\x80") == r + r);                      // overlong
    CHECK(xml_escape("\xED\xA0\x80") == r + r + r);              // a surrogate
    CHECK(xml_escape("\xEF\xBF\xBE") == r + r + r);              // U+FFFE: not an XML character
    // 0xF5-0xFF lead no sequence: each byte is replaced, continuation bytes included.
    CHECK(xml_escape("\xF5\x80\x80") == r + r + r);
    CHECK(xml_escape("\xF7\xBF\xBF\xBF") == r + r + r + r);
    CHECK(xml_escape("\xF8\x88\x80\x80\x80") == r + r + r + r + r);
    CHECK(xml_escape("\xFF"
                     "a") == r + "a");
}

TEST_CASE("the API description lists libs functions variables and handles", "[test][fake]") {
    auto api = Rhp::test::describe_api(install_arena());
    REQUIRE(api);
    const std::string json = Rhp::json::to_text(*api);
    INFO(json);
    CHECK(json.find("\"name\":\"arena\"") != std::string::npos);
    CHECK(json.find("\"name\":\"spawn\",\"params\":[\"string\",\"integer\"],\"returns\":[\"integer\"]") != std::string::npos);
    CHECK(json.find("\"name\":\"gravity\",\"type\":\"number\",\"writable\":true") != std::string::npos);
    CHECK(json.find("\"name\":\"unit\",\"methods\":[{\"name\":\"move\",\"params\":[\"integer\"]") != std::string::npos);
}

TEST_CASE("libs faked from a description stand in for the program", "[test][fake]") {
    auto api = Rhp::test::describe_api(install_arena());
    REQUIRE(api);
    Rhp::test::run_options o = options_for({"fakes_spec.lua"});
    o.api = *api;
    run x = run_specs(o, {}); // no real libs at all
    INFO(x.text);
    check_conventions(x);
    const auto* typed = find(x.result, "description fakes arguments are type checked (errors)");
    REQUIRE(typed != nullptr);
    CHECK(typed->message.find("string") != std::string::npos);
    CHECK(g_spawned.empty());

    o.strict_fakes = true;
    x = run_specs(o, {});
    const auto* strict = find(x.result, "description fakes functions record calls and return defaults (ok)");
    REQUIRE(strict != nullptr);
    CHECK(strict->outcome == status::kError);
    CHECK(strict->message.find("not mocked") != std::string::npos);
}

TEST_CASE("fake of a lib records calls instead of reaching the program", "[test][fake]") {
    const Rhp::test::install_fn install = [](Rhp::script::sandbox& box) { return box.install<Rhp::test::fake<arena_lib>>(); };
    Rhp::test::fake_registry::instance().set_returns("arena.count", {Rhp::value{std::int64_t{42}}}); // from C++: kept for every test
    const Rhp::utils::scope_guard forget{[]() noexcept { Rhp::test::fake_registry::instance().reset(); }};
    Rhp::test::run_options o = options_for({"fake_cpp_spec.lua"});
    run x = run_specs(o, install);
    INFO(x.text);
    check_conventions(x);
    CHECK(g_spawned.empty());
    CHECK(g_gravity == 9.5);
    CHECK(Rhp::test::fake_registry::instance().calls("arena.spawn").empty()); // reset for each test
    CHECK(Rhp::test::fake_registry::instance().returns("arena.count").has_value());
    CHECK_FALSE(Rhp::test::fake_registry::instance().returns("arena.spawn").has_value()); // set from Lua: gone

    o.strict_fakes = true;
    x = run_specs(o, install);
    const auto* strict = find(x.result, "fake<L> calls are recorded with their arguments (ok)");
    REQUIRE(strict != nullptr);
    CHECK(strict->outcome == status::kError);
    CHECK(strict->message.find("not mocked") != std::string::npos);
    CHECK_FALSE(Rhp::test::fake_registry::instance().strict());
}

TEST_CASE("fake results the last test set from Lua end with the run", "[test][fake]") {
    const Rhp::test::install_fn install = [](Rhp::script::sandbox& box) { return box.install<Rhp::test::fake<arena_lib>>(); };
    const Rhp::utils::scope_guard forget{[]() noexcept { Rhp::test::fake_registry::instance().reset(); }};
    Rhp::test::run_options o = options_for({"fake_cpp_spec.lua"});
    o.filters.emplace_back("fake.returns sets results"); // the only test: nothing runs after it
    const run x = run_specs(o, install);
    INFO(x.text);
    CHECK(x.result.totals.passed == 1);
    CHECK_FALSE(Rhp::test::fake_registry::instance().returns("arena.spawn").has_value());
}

namespace runner_tests_fixture {

struct fake_point {
    float x = 1;
    float y = 2;
};

inline float g_fake_samples[3] = {1, 2, 3};
inline fake_point g_fake_point{};

inline std::span<float> fake_samples() {
    return g_fake_samples;
}

inline fake_point* fake_find(int) {
    return &g_fake_point;
}

inline fake_point& fake_main() {
    return g_fake_point;
}

inline float fake_total(std::span<const float> v) {
    return v.empty() ? 0.0f : v[0];
}

using view_lib = Rhp::lib<"fviews">::view<"point", fake_point>::field<"x", &fake_point::x>::field<"y", &fake_point::y> //
    ::fn<"samples", &fake_samples>::fn<"find", &fake_find>::fn<"main", &fake_main>::fn<"total", &fake_total>;

} // namespace runner_tests_fixture

TEST_CASE("fake of a lib with views returns empty spans nil and default objects", "[test][fake][views]") {
    Rhp::script::sandbox box;
    REQUIRE(box.install<Rhp::test::fake<view_lib>>());
    const Rhp::utils::scope_guard forget{[]() noexcept { Rhp::test::fake_registry::instance().reset(); }};
    const auto r = box.exec("local p = fviews.main() p.x = 5 return #fviews.samples(), fviews.find(1) == nil, p.x, fviews.main().y");
    REQUIRE(r.has_value());
    CHECK(*r == Rhp::script::value_list{Rhp::value{0}, Rhp::value{true}, Rhp::value{5.0}, Rhp::value{2.0}});
    CHECK(g_fake_point.x == 1.0f); // nothing reached the program
    // A view calls its binding again on every access: two calls and three field accesses.
    CHECK(Rhp::test::fake_registry::instance().calls("fviews.main").size() == 5);
    CHECK(box.revert_all().clean());
}

TEST_CASE("libs with views faked from a description stand in for the program", "[test][fake][views]") {
    auto api = Rhp::test::describe_api([](Rhp::script::sandbox& box) { return box.install<view_lib>(); });
    REQUIRE(api);
    Rhp::test::run_options o = options_for({"views_fakes_spec.lua"});
    o.api = *api;
    run x = run_specs(o, {}); // no real libs at all
    INFO(x.text);
    check_conventions(x);
    REQUIRE(find(x.result, "described views fake view bindings return empty spans nil and default objects (ok)") != nullptr);
    CHECK(g_fake_point.x == 1.0f);
}

namespace runner_tests_fixture {

struct cli_run {
    int status = 0;
    std::string out;
    std::string err;
};

cli_run run_cli(std::vector<std::string> args, const Rhp::test::install_fn& install = install_arena()) {
    std::vector<std::string_view> views{args.begin(), args.end()};
    std::ostringstream out;
    std::ostringstream err;
    reset();
    const int status = Rhp::test::run_cli(views, install, "lua-tests", out, err);
    return {status, out.str(), err.str()};
}

Rhp::result<Rhp::test::cli_options> parse(std::vector<std::string_view> args) {
    return Rhp::test::parse_args(args);
}

} // namespace runner_tests_fixture

TEST_CASE("arguments parse into options", "[test][cli]") {
    auto p = parse({"specs", "-s", "scripts", "--filter", "combat", "--filter-out", "slow", "-t", "a,b", "--exclude-tags", "net", "--seed", "7", "--shuffle",
                    "--repeat", "3", "--fail-fast", "--isolation", "test", "--role", "admin", "--timeout", "250", "--max-frames", "99", "--instructions", "1000",
                    "--memory", "4096", "-r", "junit:out/j.xml", "-r", "tap", "-v", "--coverage", "lcov", "--coverage", "cobertura:c.xml", "--coverage-tests",
                    "--profile=50", "--profile-out", "p.folded", "--no-measure", "--strict-undo", "--ci", "-u", "--fuzz", "300", "--property-runs", "20",
                    "--api", "api.json", "--strict-fakes", "--list", "--no-color", "--root", "r", "--epoch", "86400"});
    REQUIRE(p);
    const Rhp::test::run_options& o = p->run;
    CHECK(o.tests == std::vector<fs::path>{"specs"});
    CHECK(o.scripts == std::vector<fs::path>{"scripts"});
    CHECK(o.filters == std::vector<std::string>{"combat"});
    CHECK(o.filters_out == std::vector<std::string>{"slow"});
    CHECK(o.tags == std::vector<std::string>{"a", "b"});
    CHECK(o.exclude_tags == std::vector<std::string>{"net"});
    CHECK(o.seed == 7u);
    CHECK(o.shuffle);
    CHECK(o.repeat == 3);
    CHECK(o.fail_fast);
    CHECK(o.share == Rhp::test::isolation::kTest);
    CHECK(o.caller == Rhp::role::kAdmin);
    CHECK(o.timeout == std::chrono::milliseconds{250});
    CHECK(o.max_frames == 99);
    CHECK(o.limits.instructions == 1000);
    CHECK(o.limits.memory == 4096);
    REQUIRE(o.reports.size() == 2);
    CHECK(o.reports[0].kind == Rhp::test::report_kind::kJunit);
    CHECK(o.reports[0].path == fs::path{"out/j.xml"});
    CHECK(o.reports[1].kind == Rhp::test::report_kind::kTap);
    CHECK(o.reports[1].path.empty());
    CHECK(o.verbose);
    REQUIRE(o.coverage.size() == 2);
    CHECK(o.coverage[0].path == fs::path{"lcov.info"});
    CHECK(o.coverage[1].kind == Rhp::test::coverage_kind::kCobertura);
    CHECK(o.coverage[1].path == fs::path{"c.xml"});
    CHECK(o.coverage_tests);
    CHECK(o.profile);
    CHECK(o.profile_interval == 50);
    CHECK(o.profile_out == fs::path{"p.folded"});
    CHECK_FALSE(o.measure);
    CHECK(o.strict_undo);
    CHECK(o.ci);
    CHECK(o.update_snapshots);
    CHECK(o.fuzz_ms == 300u);
    CHECK(o.property_runs == 20);
    CHECK(p->api_file == fs::path{"api.json"});
    CHECK(o.strict_fakes);
    CHECK(o.list_only);
    CHECK(o.color == false);
    CHECK(o.root == fs::path{"r"});
    CHECK(o.epoch == 86400);

    CHECK(parse({"--help"})->help);
    CHECK(parse({"-r", "C:/reports/x.txt"}).error().message.find("unknown reporter") != std::string::npos);
    CHECK(parse({"-r", "junit:C:/reports/x.xml"})->run.reports[0].path == fs::path{"C:/reports/x.xml"});
    for (const auto& bad : std::vector<std::vector<std::string_view>>{
             {"--bogus"}, {"--seed", "x"}, {"--seed"}, {"--repeat", "0"}, {"--isolation", "module"}, {"--role", "root"}, {"--timeout", "0"}, {"-r", "html"}, {"--coverage", "gcov"}, {"--profile=x"}, {"--property-runs", "0"}, {"--max-frames", "-1"}}) {
        INFO(bad[0]);
        const auto r = parse(bad);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == Rhp::errc::kInvalidArgument);
    }
}

TEST_CASE("the command line runs tests and writes reports", "[test][cli]") {
    const temp_tree tree{"cli", {"basics_spec.lua", "isolation_spec.lua", "coverage_spec.lua"}};
    const std::string root = tree.root.generic_string();
    const std::string specs = (tree.root / "specs").generic_string();
    const std::string scripts = (tree.root / "scripts").generic_string();

    cli_run r = run_cli({"--help"});
    CHECK(r.status == 0);
    CHECK(r.out.starts_with("usage: lua-tests"));
    r = run_cli({});
    CHECK(r.status == 2);
    CHECK(r.err.find("no test files") != std::string::npos);
    r = run_cli({"--bogus"});
    CHECK(r.status == 2);

    r = run_cli({specs + "/isolation_spec.lua", "-s", scripts, "--root", root, "--no-color"});
    INFO(r.out << r.err);
    CHECK(r.status == 0);
    CHECK(r.out.find("2 passed") != std::string::npos);

    r = run_cli({specs + "/basics_spec.lua", specs + "/coverage_spec.lua", "-s", scripts, "--root", root, "--seed", "1", "-r", "text",
                 "-r", "junit:" + root + "/out/junit.xml", "-r", "json:" + root + "/out/events.jsonl", "-r", "tap:" + root + "/out/tap.txt",
                 "--coverage", "summary", "--coverage", "lcov:" + root + "/out/lcov.info", "--coverage", "cobertura:" + root + "/out/cobertura.xml",
                 "--profile-out", root + "/out/profile.folded"});
    CHECK(r.status == 1); // basics has failures
    CHECK(r.out.find("seed 1") != std::string::npos);
    CHECK(r.out.find("scripts/game/combat.lua") != std::string::npos); // the coverage summary
    CHECK(temp_tree::read_file(tree.root / "out" / "junit.xml").find("<testsuites") != std::string::npos);
    CHECK(temp_tree::read_file(tree.root / "out" / "events.jsonl").find("\"event\":\"run_end\"") != std::string::npos);
    CHECK(temp_tree::read_file(tree.root / "out" / "tap.txt").starts_with("TAP version 14"));
    CHECK(temp_tree::read_file(tree.root / "out" / "lcov.info").find("SF:scripts/game/combat.lua") != std::string::npos);
    CHECK(temp_tree::read_file(tree.root / "out" / "cobertura.xml").find("<coverage") != std::string::npos);
    CHECK(temp_tree::read_file(tree.root / "out" / "profile.folded").find("sum") != std::string::npos);

    // Folders are searched; --list doesn't run anything.
    r = run_cli({specs, "-s", scripts, "--root", root, "--list"});
    CHECK(r.status == 0);
    CHECK(r.out.find("specs/basics_spec.lua:5  damage subtracts armor") != std::string::npos);
    CHECK(r.out.find("specs/isolation_spec.lua") != std::string::npos);
    CHECK(r.out.find("(skipped)") != std::string::npos);
    r = run_cli({specs, "-s", scripts, "--root", root, "--list", "-r", "json", "-t", "fast"});
    CHECK(r.status == 0);
    const auto first = Rhp::json::parse(r.out.substr(0, r.out.find('\n')));
    REQUIRE(first);
    CHECK(first->find("event")->get_if<std::string>() != nullptr);
    CHECK(r.out.find("handles tables and strings #fast") != std::string::npos);
    CHECK(r.out.find("damage subtracts armor") == std::string::npos);
}

TEST_CASE("the API description round trips through a file", "[test][cli]") {
    const temp_tree tree{"api", {"fakes_spec.lua"}};
    const std::string root = tree.root.generic_string();
    const std::string api = root + "/out/api.json";
    cli_run r = run_cli({"--dump-api", api});
    CHECK(r.status == 0);
    REQUIRE(fs::exists(api));
    CHECK(Rhp::json::parse(temp_tree::read_file(api)).has_value());

    r = run_cli({root + "/specs/fakes_spec.lua", "-s", root + "/scripts", "--root", root, "--api", api, "--filter-out", "type checked"}, {});
    INFO(r.out << r.err);
    CHECK(r.status == 0);
    r = run_cli({root + "/specs/fakes_spec.lua", "--api", root + "/missing.json"}, {});
    CHECK(r.status == 2);
    temp_tree::write_file(tree.root / "bad.json", "{\"not\": \"an api\"}");
    r = run_cli({root + "/specs/fakes_spec.lua", "--api", root + "/bad.json"}, {});
    CHECK(r.status == 2);
    CHECK(r.err.find("isn't an API description") != std::string::npos);
}

TEST_CASE("the embedded fixtures are the source tree's", "[test][fixtures]") {
    const fs::path source{RHP_TEST_FIXTURES};
    std::error_code ec;
    if (!fs::exists(source, ec)) {
        SKIP("the source tree isn't reachable here");
    }
    const auto without_cr = [](std::string text) {
        std::erase(text, '\r');
        return text;
    };
    std::vector<std::string> embedded;
    for (const auto& f : rhp_test_fixtures::fixture_files()) {
        embedded.emplace_back(f.name);
        INFO(f.name);
        CHECK(without_cr(std::string{f.text}) == without_cr(temp_tree::read_file(source.parent_path() / fs::path{std::string{f.name}})));
    }
    // Every fixture file is listed in Tests/unit/CMakeLists.txt (snapshots and corpora a test left aside).
    for (const fs::path& dir : {source, source.parent_path() / "golden"}) {
        for (const auto& entry : fs::recursive_directory_iterator{dir}) {
            const std::string rel = fs::relative(entry.path(), source.parent_path()).generic_string();
            if (!entry.is_regular_file() || rel.find("__") != std::string::npos || rel.ends_with(".actual")) {
                continue;
            }
            INFO(rel << " isn't in rhp_test_fixture_files (Tests/unit/CMakeLists.txt)");
            CHECK(std::ranges::find(embedded, rel) != embedded.end());
        }
    }
}

TEST_CASE("a test stopped by a limit still gets its cleanup", "[test][abort]") {
    Rhp::test::run_options o = options_for({"abort_spec.lua"});
    o.limits.instructions = 2'000'000;
    const run x = run_specs(o);
    INFO(x.text);
    check_conventions(x);
    const auto* runaway = find(x.result, "aborted runs away (errors)");
    REQUIRE(runaway != nullptr);
    bool noted = false;
    for (const std::string& n : runaway->notes) {
        noted = noted || n.find("runaway_global") != std::string::npos;
    }
    CHECK(noted);
}

TEST_CASE("snapshots refuse duplicate names and survive being emptied", "[test][snapshot]") {
    const temp_tree tree{"snap2", {"dup_snapshot_spec.lua", "snapshot_spec.lua"}};
    run x = run_specs(tree.options({"dup_snapshot_spec.lua"}));
    INFO(x.text);
    CHECK(x.result.totals.passed == 1);
    CHECK(x.result.totals.failed == 1);
    bool refused = false;
    for (const auto& t : x.result.files[0].tests) {
        refused = refused || t.message.find("two snapshots are named 'same name 1'") != std::string::npos;
    }
    CHECK(refused);

    // Every snapshot assertion removed, then --update-snapshots: the file holds none; adding one back works.
    tree.replace("snapshot_spec.lua", "VALUE)", "{ 1 })");
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 3);
    const std::string original = temp_tree::read_file(tree.root / "specs" / "snapshot_spec.lua");
    temp_tree::write_file(tree.root / "specs" / "snapshot_spec.lua", "it('nothing (ok)', function() end)\n");
    Rhp::test::run_options update = tree.options({"snapshot_spec.lua"});
    update.update_snapshots = true;
    x = run_specs(update);
    CHECK(x.result.totals.passed == 1);
    temp_tree::write_file(tree.root / "specs" / "snapshot_spec.lua", original);
    x = run_specs(tree.options({"snapshot_spec.lua"}));
    CHECK(x.result.totals.passed == 3);
    CHECK(x.result.totals.failed == 0);
}

TEST_CASE("a module that doesn't load doesn't stop the tests", "[test][modules]") {
    const temp_tree tree{"badmod", {"isolation_spec.lua"}};
    temp_tree::write_file(tree.root / "scripts" / "game" / "broken.lua", "return +\n");
    const run x = run_specs(tree.options({"isolation_spec.lua"}));
    INFO(x.text);
    REQUIRE(x.result.files.size() == 1);
    CHECK(x.result.files[0].tests.size() == 2);
    CHECK(outcome_of(x, "second reads the module state") == status::kPassed);
    REQUIRE(x.result.files[0].errors.size() == 1);
    CHECK(x.result.files[0].errors[0].message.find("module game.broken didn't load") != std::string::npos);
    CHECK_FALSE(x.result.totals.ok());
}

TEST_CASE("a file whose modules warn still runs its teardown", "[test][modules]") {
    const temp_tree tree{"warnteardown", {}};
    temp_tree::write_file(tree.root / "scripts" / "game" / "broken.lua", "return +\n");
    temp_tree::write_file(tree.root / "specs" / "teardown_spec.lua",
                          "teardown(function() error('the teardown ran') end)\n"
                          "it('runs (ok)', function() end)\n");
    const run x = run_specs(tree.options({"teardown_spec.lua"}));
    INFO(x.text);
    REQUIRE(x.result.files.size() == 1);
    CHECK(outcome_of(x, "runs (ok)") == status::kPassed);
    const auto& errors = x.result.files[0].errors;
    REQUIRE(errors.size() == 2);
    CHECK(errors[0].message.find("module game.broken didn't load") != std::string::npos);
    CHECK(errors[1].message.find("teardown of 'the file' failed") != std::string::npos);
    CHECK(errors[1].message.find("the teardown ran") != std::string::npos);
}
