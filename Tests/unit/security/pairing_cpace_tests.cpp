// CPace (draft-irtf-cfrg-cpace-21, CPACE-X25519-SHA512): the draft's test vectors, round trips and
// the low-order point check.
#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/pairing.hpp>
#include <rhp/security/pairing_cpace.hpp>

using Rhp::errc;
using namespace Rhp::security;

namespace cpace_fixtures {

[[nodiscard]] std::vector<std::byte> cpace_hex(std::string_view hex) {
    auto nibble = [](char c) {
        return static_cast<unsigned>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    };
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

[[nodiscard]] std::array<std::byte, 32> cpace_hex32(std::string_view hex) {
    const auto bytes = cpace_hex(hex);
    std::array<std::byte, 32> out{};
    std::copy_n(bytes.begin(), out.size(), out.begin());
    return out;
}

[[nodiscard]] std::span<const std::byte> cpace_text(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}

// Appendix B.1 of the draft.
constexpr std::string_view kB1Prs = "Password";
constexpr std::string_view kB1Ci = "0b415f696e69746961746f720b425f726573706f6e646572";
constexpr std::string_view kB1Sid = "7e4b4791d6a8ef019b936c79fb7f2c57";
constexpr std::string_view kB1Generator = "d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f";
constexpr std::string_view kB1Ya = "21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080";
constexpr std::string_view kB1YaPoint = "1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32";
constexpr std::string_view kB1Yb = "848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a";
constexpr std::string_view kB1YbPoint = "248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623";
constexpr std::string_view kB1K = "5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b";
constexpr std::string_view kB1IskIr = "6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2"
                                      "aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263";

[[nodiscard]] std::vector<std::byte> cpace_vector(std::span<const std::byte> bytes) {
    return {bytes.begin(), bytes.end()};
}

} // namespace cpace_fixtures

using namespace cpace_fixtures;

TEST_CASE("cpace: the draft's X25519 generator vector", "[security][cpace]") {
    const auto ci = cpace_hex(kB1Ci);
    const auto sid = cpace_hex(kB1Sid);
    auto g = cpace_generator(cpace_text(kB1Prs), ci, sid);
    REQUIRE(g);
    CHECK(to_hex(*g) == kB1Generator);
}

TEST_CASE("cpace: the draft's X25519 message K and ISK vectors", "[security][cpace]") {
    const auto ci = cpace_hex(kB1Ci);
    const auto sid = cpace_hex(kB1Sid);
    const auto ya = cpace_hex32(kB1Ya);
    const auto yb = cpace_hex32(kB1Yb);

    auto a = cpace::start(cpace_role::kInitiator, {.prs = cpace_text(kB1Prs), .ci = ci, .sid = sid, .ad = cpace_text("ADa")}, ya);
    auto b = cpace::start(cpace_role::kResponder, {.prs = cpace_text(kB1Prs), .ci = ci, .sid = sid, .ad = cpace_text("ADb")}, yb);
    REQUIRE(a);
    REQUIRE(b);
    CHECK(to_hex(a->message()) == kB1YaPoint);
    CHECK(to_hex(b->message()) == kB1YbPoint);

    auto k_a = detail::cpace_scalar_mult_vfy(ya, cpace_hex32(kB1YbPoint));
    auto k_b = detail::cpace_scalar_mult_vfy(yb, cpace_hex32(kB1YaPoint));
    REQUIRE(k_a);
    REQUIRE(k_b);
    CHECK(to_hex(*k_a) == kB1K);
    CHECK(to_hex(*k_b) == kB1K);

    auto isk_a = a->finish(b->message(), cpace_text("ADb"));
    auto isk_b = b->finish(a->message(), cpace_text("ADa"));
    REQUIRE(isk_a);
    REQUIRE(isk_b);
    CHECK(isk_a->bytes().size() == cpace::kIskSize);
    CHECK(to_hex(isk_a->bytes()) == kB1IskIr);
    CHECK(to_hex(isk_b->bytes()) == kB1IskIr);
}

TEST_CASE("cpace: the draft's low-order point vectors", "[security][cpace]") {
    const auto s = cpace_hex32("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
    struct low_order {
        std::string_view u;
        std::string_view q;
    };
    constexpr std::string_view kZero = "0000000000000000000000000000000000000000000000000000000000000000";
    const std::array<low_order, 12> vectors{{
        {"0000000000000000000000000000000000000000000000000000000000000000", kZero},
        {"0100000000000000000000000000000000000000000000000000000000000000", kZero},
        {"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", kZero},
        {"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", kZero},
        {"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", kZero},
        {"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", kZero},
        {"daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806"},
        {"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", kZero},
        {"dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38"},
        {"d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456"},
        {"cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a"},
        {"4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175"},
    }};
    for (const auto& [u, q] : vectors) {
        INFO("u = " << u);
        auto out = detail::cpace_scalar_mult_vfy(s, cpace_hex32(u));
        REQUIRE(out);
        CHECK(to_hex(*out) == q);
    }
}

TEST_CASE("cpace: a low-order peer message fails with kAuth", "[security][cpace]") {
    // u0..u5 and u7 of the draft must abort the run.
    constexpr std::array<std::string_view, 7> kAbort{
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    for (const auto u : kAbort) {
        INFO("u = " << u);
        auto run = cpace::start(cpace_role::kResponder, {.prs = cpace_text("123456")});
        REQUIRE(run);
        auto isk = run->finish(cpace_hex(u));
        REQUIRE_FALSE(isk);
        CHECK(isk.error().code == errc::kAuth);
    }
}

TEST_CASE("cpace: initiator and responder agree on the ISK", "[security][cpace]") {
    const auto sid = cpace_text("session 1");
    for (int i = 0; i < 16; ++i) {
        auto a = cpace::start(cpace_role::kInitiator, {.prs = cpace_text("042133"), .ci = cpace_text("ci"), .sid = sid, .ad = cpace_text("client")});
        auto b = cpace::start(cpace_role::kResponder, {.prs = cpace_text("042133"), .ci = cpace_text("ci"), .sid = sid, .ad = cpace_text("host")});
        REQUIRE(a);
        REQUIRE(b);
        CHECK(cpace_vector(a->message()) != cpace_vector(b->message()));
        auto isk_a = a->finish(b->message(), b->associated_data());
        auto isk_b = b->finish(a->message(), a->associated_data());
        REQUIRE(isk_a);
        REQUIRE(isk_b);
        CHECK(cpace_vector(isk_a->bytes()) == cpace_vector(isk_b->bytes()));
    }
}

TEST_CASE("cpace: different inputs give different ISKs", "[security][cpace]") {
    struct side {
        std::string_view prs = "042133";
        std::string_view ci = "ci";
        std::string_view sid = "sid";
        std::string_view ad_a = "a";
        std::string_view ad_b = "b"; // what A believes B sent
    };
    auto run = [](const side& a_view, const side& b_view) {
        auto a = cpace::start(cpace_role::kInitiator, {.prs = cpace_text(a_view.prs), .ci = cpace_text(a_view.ci), .sid = cpace_text(a_view.sid), .ad = cpace_text(a_view.ad_a)});
        auto b = cpace::start(cpace_role::kResponder, {.prs = cpace_text(b_view.prs), .ci = cpace_text(b_view.ci), .sid = cpace_text(b_view.sid), .ad = cpace_text(b_view.ad_b)});
        REQUIRE(a);
        REQUIRE(b);
        auto isk_a = a->finish(b->message(), cpace_text(a_view.ad_b));
        auto isk_b = b->finish(a->message(), cpace_text(b_view.ad_a));
        REQUIRE(isk_a);
        REQUIRE(isk_b);
        return cpace_vector(isk_a->bytes()) == cpace_vector(isk_b->bytes());
    };
    CHECK(run({}, {}));
    CHECK_FALSE(run({}, {.prs = "042134"}));
    CHECK_FALSE(run({}, {.ci = "other"}));
    CHECK_FALSE(run({}, {.sid = "other"}));
    CHECK_FALSE(run({}, {.ad_a = "x"}));
    CHECK_FALSE(run({.ad_b = "x"}, {}));
}

TEST_CASE("cpace: finish runs once and checks the message size", "[security][cpace]") {
    auto a = cpace::start(cpace_role::kInitiator, {.prs = cpace_text("1")});
    auto b = cpace::start(cpace_role::kResponder, {.prs = cpace_text("1")});
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->finish(std::span{a->message()}.first(31)).error().code == errc::kInvalidArgument);
    REQUIRE(a->finish(b->message()));
    CHECK(a->finish(b->message()).error().code == errc::kInvalidArgument);
}

TEST_CASE("cpace: pairing codes agree only on the same code and channel", "[security][cpace]") {
    const std::array<std::byte, 4> exporter{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> relayed{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{5}};
    auto agree = [](std::string_view code_a, std::span<const std::byte> binding_a, std::string_view code_b, std::span<const std::byte> binding_b) {
        auto prs_a = pairing_code_prs(code_a);
        auto prs_b = pairing_code_prs(code_b);
        REQUIRE(prs_a);
        REQUIRE(prs_b);
        const auto ci_a = pairing_channel_id(binding_a);
        const auto ci_b = pairing_channel_id(binding_b);
        auto a = cpace::start(cpace_role::kInitiator, {.prs = prs_a->bytes(), .ci = ci_a, .ad = cpace_text("phone")});
        auto b = cpace::start(cpace_role::kResponder, {.prs = prs_b->bytes(), .ci = ci_b, .ad = cpace_text("host")});
        REQUIRE(a);
        REQUIRE(b);
        auto isk_a = a->finish(b->message(), b->associated_data());
        auto isk_b = b->finish(a->message(), a->associated_data());
        REQUIRE(isk_a);
        REQUIRE(isk_b);
        return cpace_vector(isk_a->bytes()) == cpace_vector(isk_b->bytes());
    };
    auto code = generate_pairing_code();
    REQUIRE(code);
    CHECK(agree(*code, exporter, *code, exporter));
    CHECK_FALSE(agree("123456", exporter, "123457", exporter)); // a wrong guess
    CHECK_FALSE(agree("123456", exporter, "123456", relayed));  // two TLS connections spliced
}
