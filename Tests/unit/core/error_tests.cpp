#include <cstdint>
#include <format>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/result.hpp>

using Rhp::errc;

TEST_CASE("errc has a name for every value", "[core][error]") {
    REQUIRE(Rhp::to_string(errc::kOk) == "ok");
    REQUIRE(Rhp::to_string(errc::kForbidden) == "forbidden");
    REQUIRE(Rhp::to_string(errc::kOutOfRange) == "out_of_range");
    for (std::uint16_t i = 0; i <= static_cast<std::uint16_t>(Rhp::kLastErrc); ++i) {
        REQUIRE(Rhp::to_string(static_cast<errc>(i)) != "unknown");
    }
}

TEST_CASE("parse_errc reads what to_string writes", "[core][error]") {
    for (std::uint16_t i = 0; i <= static_cast<std::uint16_t>(Rhp::kLastErrc); ++i) {
        const auto code = static_cast<errc>(i);
        REQUIRE(Rhp::parse_errc(Rhp::to_string(code)) == code);
    }
    STATIC_REQUIRE(Rhp::parse_errc("bad_signature") == errc::kBadSignature);
    CHECK_FALSE(Rhp::parse_errc("unknown"));
    CHECK_FALSE(Rhp::parse_errc(""));
    CHECK_FALSE(Rhp::parse_errc("Forbidden"));
}

TEST_CASE("error formats code where and message", "[core][error]") {
    REQUIRE(std::format("{}", Rhp::make_error(errc::kForbidden, "needs role patch", "game.spawn")) ==
            "[forbidden] game.spawn: needs role patch");
    REQUIRE(std::format("{}", Rhp::make_error(errc::kTimeout, "no pong")) == "[timeout] no pong");
    REQUIRE(std::format("{}", Rhp::make_error(errc::kCancelled)) == "[cancelled]");
}

TEST_CASE("fail builds an unexpected result", "[core][error]") {
    const Rhp::result<int> r = Rhp::fail(errc::kNotFound, "no module 'x'");
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().code == errc::kNotFound);
    REQUIRE(r.error().message == "no module 'x'");
}

TEST_CASE("unwrap returns the value or throws Rhp::exception", "[core][error]") {
    REQUIRE(Rhp::unwrap(Rhp::result<int>{7}) == 7);
    REQUIRE_NOTHROW(Rhp::unwrap(Rhp::result<void>{}));

    try {
        (void)Rhp::unwrap(Rhp::result<int>{Rhp::fail(errc::kAuth, "bad key")});
        FAIL("expected a throw");
    } catch (const Rhp::exception& e) {
        REQUIRE(e.err().code == errc::kAuth);
        REQUIRE(std::string{e.what()} == "[auth] bad key");
    }
}
