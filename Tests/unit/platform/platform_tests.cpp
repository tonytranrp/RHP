#include <array>
#include <cstddef>
#include <set>
#include <span>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>

TEST_CASE("platform: the OS name is one of the five", "[platform][os]") {
    constexpr std::string_view name = Rhp::platform::kOsName;
    STATIC_REQUIRE(!name.empty());
    const std::set<std::string_view> known{"windows", "linux", "macos", "ios", "android"};
    CHECK(known.contains(name));
}

TEST_CASE("platform: random bytes differ between calls", "[platform][random]") {
    auto a = Rhp::platform::random_array<32>();
    auto b = Rhp::platform::random_array<32>();
    REQUIRE(a);
    REQUIRE(b);
    CHECK(*a != *b);
    // A large request is filled completely (the chance of a zero tail of 64 bytes is nil).
    std::array<std::byte, 4096> big{};
    REQUIRE(Rhp::platform::random_bytes(big));
    bool tail_nonzero = false;
    for (std::size_t i = big.size() - 64; i < big.size(); ++i) {
        tail_nonzero = tail_nonzero || big[i] != std::byte{0};
    }
    CHECK(tail_nonzero);
    CHECK(Rhp::platform::random_bytes(std::span<std::byte>{}));
}
