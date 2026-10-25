// Coroutine yields, many of them, through every path that suspends Lua: coroutine.yield, rhp.wait
// across pumps, yields inside pcall, errors after yields. Built twice on x64 MSVC: in
// rhp_script_tests (yields jump: cmake/lua/lua_cxx.cpp) and in rhp_script_cet_tests, linked
// /CETCOMPAT, where a CET shadow stack makes yields throw instead.
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/value.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::script::sandbox;

TEST_CASE("ten thousand coroutine yields come back in order", "[script][yield]") {
    sandbox box;
    const auto sum = box.exec<long long>(R"(
        local co = coroutine.wrap(function() for i = 1, 10000 do coroutine.yield(i) end end)
        local s = 0
        for _ = 1, 10000 do s = s + co() end
        return s
    )");
    REQUIRE(sum);
    CHECK(*sum == 50005000);
}

TEST_CASE("a request waiting frames resumes on every pump", "[script][yield]") {
    sandbox box;
    REQUIRE(box.exec("for i = 1, 500 do rhp.wait(1) end"));
    for (int i = 0; i < 499; ++i) {
        CHECK(box.suspended() == 1);
        box.pump();
    }
    box.pump();
    CHECK(box.suspended() == 0);
    CHECK(box.exec<int>("return 1") == 1);
}

TEST_CASE("yields inside pcall and errors after yields", "[script][yield]") {
    sandbox box;
    const auto across_pcall = box.exec(R"(
        local co = coroutine.wrap(function()
            local ok, v = pcall(function() for i = 1, 100 do coroutine.yield(i) end return "done" end)
            return ok, v
        end)
        for _ = 1, 100 do co() end
        return co()
    )");
    REQUIRE(across_pcall);
    REQUIRE(across_pcall->size() == 2);
    CHECK((*across_pcall)[0] == Rhp::value{true});
    CHECK((*across_pcall)[1] == Rhp::value{"done"});

    const auto after_yield = box.exec(R"(
        local co = coroutine.create(function() for i = 1, 100 do coroutine.yield(i) end error("boom", 0) end)
        for _ = 1, 100 do assert(coroutine.resume(co)) end
        return coroutine.resume(co)
    )");
    REQUIRE(after_yield);
    REQUIRE(after_yield->size() == 2);
    CHECK((*after_yield)[0] == Rhp::value{false});
    CHECK((*after_yield)[1] == Rhp::value{"boom"});

    const auto uncaught = box.exec("for i = 1, 10 do rhp.wait(1) end error('late failure', 0)");
    REQUIRE(uncaught); // suspended: the failure comes at the tenth pump
    for (int i = 0; i < 10; ++i) {
        box.pump();
    }
    CHECK(box.suspended() == 0);
    CHECK(box.exec<int>("return 2") == 2);
}
