#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/byte_buffer.hpp>

using Rhp::utils::byte_buffer;

TEST_CASE("byte_buffer writes little-endian integers", "[utils][byte_buffer]") {
    byte_buffer buf;
    buf.append_le<std::uint16_t>(0x1234);
    buf.append_le<std::uint32_t>(0xAABBCCDDu);
    REQUIRE(buf.size() == 6);
    const auto v = buf.view();
    REQUIRE(v[0] == std::byte{0x34});
    REQUIRE(v[1] == std::byte{0x12});
    REQUIRE(v[2] == std::byte{0xDD});
    REQUIRE(v[5] == std::byte{0xAA});
}

TEST_CASE("byte_buffer read_le round-trips and bounds-checks", "[utils][byte_buffer]") {
    byte_buffer buf;
    buf.append_le<std::uint64_t>(0x0102030405060708ull);
    buf.append_le<std::uint8_t>(0x7F);
    REQUIRE(buf.read_le<std::uint64_t>(0) == 0x0102030405060708ull);
    REQUIRE(buf.read_le<std::uint8_t>(8) == 0x7F);
    REQUIRE_FALSE(buf.read_le<std::uint16_t>(8).has_value());
    REQUIRE_FALSE(buf.read_le<std::uint8_t>(9).has_value());
    REQUIRE_FALSE(buf.read_le<std::uint8_t>(1000).has_value());
}

TEST_CASE("byte_buffer append text and compare", "[utils][byte_buffer]") {
    byte_buffer a;
    byte_buffer b;
    a.append("rhp");
    b.append(Rhp::utils::as_bytes("rhp"));
    REQUIRE(a == b);
    b.append_le<std::uint8_t>(0);
    REQUIRE_FALSE(a == b);
    a.clear();
    REQUIRE(a.empty());
}

TEST_CASE("byte_buffer allocates from the injected memory resource", "[utils][byte_buffer]") {
    std::array<std::byte, 256> storage{};
    std::pmr::monotonic_buffer_resource arena{storage.data(), storage.size(), std::pmr::null_memory_resource()};
    byte_buffer buf{&arena};
    buf.append("fits in the arena");
    REQUIRE(buf.size() == 17);
}

TEST_CASE("byte_buffer appends large and small pieces and its own bytes", "[utils][byte_buffer]") {
    byte_buffer buf;
    std::array<std::byte, 5000> big{};
    for (std::size_t i = 0; i < big.size(); ++i) {
        big[i] = static_cast<std::byte>(i * 7u);
    }
    for (int i = 0; i < 3; ++i) {
        buf.append(std::span<const std::byte>{big});
        buf.append_le<std::uint8_t>(static_cast<std::uint8_t>(i));
    }
    REQUIRE(buf.size() == 3 * (big.size() + 1));
    REQUIRE(buf.view()[big.size()] == std::byte{0});
    REQUIRE(buf.view()[2 * (big.size() + 1) + 4999] == big[4999]);

    // Appending a view of the buffer itself survives the reallocation the append needs.
    byte_buffer self;
    self.append("abcdef");
    for (int i = 0; i < 12; ++i) {
        self.append(self.view());
    }
    REQUIRE(self.size() == 6u << 12);
    for (std::size_t i = 0; i < self.size(); i += 997) {
        REQUIRE(self.view()[i] == static_cast<std::byte>("abcdef"[i % 6]));
    }
}
