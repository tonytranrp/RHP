// Rhp::test with RHP_ENABLE=OFF: no Lua, so test files report that they can't run; the API is still
// described, the options still parse, and fakes still compile.
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/json.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/test.hpp>

namespace fs = std::filesystem;

namespace disabled_test_fixture {

inline int twice(int x) {
    return 2 * x;
}

using game_lib = Rhp::lib<"game">::fn<"twice", &twice>;

const fs::path kFixtures{RHP_TEST_FIXTURES};

} // namespace disabled_test_fixture

using namespace disabled_test_fixture;

TEST_CASE("without Lua test files report that they can't run", "[test][disabled]") {
    Rhp::test::run_options o;
    o.root = kFixtures;
    o.tests.push_back(kFixtures / "specs" / "basics_spec.lua");
    std::ostringstream out;
    auto report = Rhp::test::make_text_reporter(out, false, false);
    Rhp::test::runner r{o, [](Rhp::script::sandbox& box) { return box.install<game_lib>(); }};
    const Rhp::test::run_result result = r.run(*report);
    REQUIRE(result.files.size() == 1);
    REQUIRE(result.files[0].errors.size() == 1);
    CHECK(result.files[0].errors[0].message.find("RHP_ENABLE=OFF") != std::string::npos);
    CHECK_FALSE(result.totals.ok());

    // Listing says the same, not why a sandbox couldn't enable testing.
    const auto listed = r.list();
    REQUIRE(listed.size() == 1);
    CHECK(listed[0].second.empty());
    REQUIRE(listed[0].first.errors.size() == 1);
    CHECK(listed[0].first.errors[0].message == result.files[0].errors[0].message);
}

TEST_CASE("without Lua the API is still described and fakes still build", "[test][disabled]") {
    auto api = Rhp::test::describe_api([](Rhp::script::sandbox& box) { return box.install<game_lib>(); });
    REQUIRE(api);
    CHECK(Rhp::json::to_text(*api).find("\"name\":\"twice\"") != std::string::npos);
    Rhp::script::sandbox box{Rhp::script::sandbox_options{}};
    CHECK(box.install<Rhp::test::fake<game_lib>>().error().code == Rhp::errc::kDisabled);

    const std::vector<std::string_view> args{"specs", "--seed", "3"};
    auto parsed = Rhp::test::parse_args(args);
    REQUIRE(parsed);
    CHECK(parsed->run.seed == 3u);
    std::ostringstream out;
    std::ostringstream err;
    const std::string spec = (kFixtures / "specs" / "basics_spec.lua").generic_string();
    const std::vector<std::string_view> run_args{spec};
    CHECK(Rhp::test::run_cli(run_args, {}, "lua-tests", out, err) == 1);
}
