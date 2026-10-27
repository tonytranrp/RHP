#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>

using Rhp::errc;
using Rhp::security::key;

namespace {

std::vector<std::byte> bytes_of(std::string_view s) {
    std::vector<std::byte> out;
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

} // namespace

TEST_CASE("base64: RFC 4648 vectors", "[security][base64]") {
    using Rhp::security::base64_decode;
    using Rhp::security::base64_encode;
    CHECK(base64_encode(bytes_of("")) == "");
    CHECK(base64_encode(bytes_of("f")) == "Zg==");
    CHECK(base64_encode(bytes_of("fo")) == "Zm8=");
    CHECK(base64_encode(bytes_of("foo")) == "Zm9v");
    CHECK(base64_encode(bytes_of("foobar")) == "Zm9vYmFy");
    for (const char* text : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        auto back = base64_decode(base64_encode(bytes_of(text)));
        REQUIRE(back);
        CHECK(*back == bytes_of(text));
    }
    CHECK(base64_decode("  Zm9v\n"));
    CHECK_FALSE(base64_decode("Zm9"));
    CHECK_FALSE(base64_decode("Zm9!"));
    CHECK_FALSE(base64_decode("Z===")); // padding too early
    CHECK_FALSE(base64_decode("Zg==Zg=="));
}

TEST_CASE("key: size rules and text forms", "[security][key]") {
    CHECK_FALSE(key::from_bytes(std::vector<std::byte>(15)));
    CHECK_FALSE(key::from_bytes(std::vector<std::byte>(65)));
    auto k = key::from_bytes(std::vector<std::byte>(32, std::byte{1}));
    REQUIRE(k);
    auto again = key::from_base64(k->to_base64());
    REQUIRE(again);
    CHECK(std::ranges::equal(again->bytes(), k->bytes()));

    auto g1 = key::generate();
    auto g2 = key::generate();
    REQUIRE(g1);
    REQUIRE(g2);
    CHECK(g1->bytes().size() == 32);
    CHECK_FALSE(std::ranges::equal(g1->bytes(), g2->bytes()));

    key moved = std::move(*g1);
    CHECK(moved.bytes().size() == 32);
    CHECK(g1->empty());
}

TEST_CASE("key: from a file and from the environment", "[security][key]") {
    auto k = key::generate();
    REQUIRE(k);
    const auto path = std::filesystem::temp_directory_path() / "rhp_key_tests.key";
    {
        std::ofstream out{path};
        out << "  " << k->to_base64() << "\n";
    }
    auto from_file = key::from_file(path.string());
    std::filesystem::remove(path);
    REQUIRE(from_file);
    CHECK(std::ranges::equal(from_file->bytes(), k->bytes()));
    CHECK(key::from_file((std::filesystem::temp_directory_path() / "rhp_no_such.key").string()).error().code == errc::kNotFound);
    CHECK(key::from_env("RHP_TESTS_SURELY_UNSET_VARIABLE").error().code == errc::kNotFound);
}

TEST_CASE("keyring: names are unique and keys required", "[security][keyring]") {
    Rhp::security::keyring ring;
    auto k = key::generate();
    REQUIRE(k);
    CHECK(ring.add({"dev", *k, Rhp::role::kAdmin}));
    CHECK(ring.add({"dev", *k, Rhp::role::kPatch}).error().code == errc::kAlreadyLoaded);
    CHECK(ring.add({"", *k, Rhp::role::kPatch}).error().code == errc::kInvalidArgument);
    CHECK(ring.add({"empty", key{}, Rhp::role::kPatch}).error().code == errc::kInvalidArgument);
    REQUIRE(ring.find("dev") != nullptr);
    CHECK(ring.find("dev")->granted == Rhp::role::kAdmin);
    CHECK(ring.find("nobody") == nullptr);
    CHECK(ring.size() == 1);
    CHECK_THROWS_AS((Rhp::security::keyring{{"a", *k, Rhp::role::kObserve}, {"a", *k, Rhp::role::kObserve}}), Rhp::exception);
}
