#include <optional>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/net/address.hpp>

using Rhp::net::ip_address;

namespace {

constexpr ip_address::bytes_type kLoopback6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

[[nodiscard]] bool parses(std::string_view text) {
    return ip_address::parse(text).has_value();
}

} // namespace

static_assert(ip_address::parse("192.168.1.20") == ip_address::v4(192, 168, 1, 20));
static_assert(ip_address::parse("::1") == ip_address{kLoopback6});
static_assert(!ip_address::parse("cafe1"));

TEST_CASE("ip_address: IPv4 text", "[net][address]") {
    CHECK(ip_address::parse("0.0.0.0") == ip_address::v4(0, 0, 0, 0));
    CHECK(ip_address::parse("255.255.255.255") == ip_address::v4(255, 255, 255, 255));
    CHECK(ip_address::parse("10.0.0.5")->is_v4());
    for (const std::string_view bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.04", "01.2.3.4", "1..2.3", "1.2.3.", ".1.2.3", "1.2.3.4 ", "1.2.3.4:80", "1.2.3.-4",
                                       "0x7f.0.0.1", "[1.2.3.4]"}) {
        INFO(bad);
        CHECK_FALSE(parses(bad));
    }
}

TEST_CASE("ip_address: IPv6 text", "[net][address]") {
    CHECK(ip_address::parse("::") == ip_address{});
    CHECK(ip_address::parse("0:0:0:0:0:0:0:1") == ip_address{kLoopback6});
    CHECK(ip_address::parse("[::1]") == ip_address{kLoopback6});
    CHECK(ip_address::parse("::ffff:10.0.0.1") == ip_address::v4(10, 0, 0, 1));
    CHECK(ip_address::parse("::FFFF:10.0.0.1")->is_v4());
    CHECK(ip_address::parse("fe80::1%eth0") == ip_address::parse("fe80::1"));
    CHECK(ip_address::parse("2001:db8::8a2e:370:7334") == ip_address{ip_address::bytes_type{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}});
    CHECK(ip_address::parse("1:2:3:4:5:6:7:8") == ip_address{ip_address::bytes_type{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}});
    CHECK(ip_address::parse("1::") == ip_address{ip_address::bytes_type{0, 1}});
    CHECK(ip_address::parse("64:ff9b::192.0.2.33") == ip_address{ip_address::bytes_type{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 33}});
    CHECK_FALSE(ip_address::parse("::1")->is_v4());
    for (const std::string_view bad : {":", ":::", "1:::2", "1::2::3", ":1::2", "1::2:", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2:3:4:5:6:7:8", "12345::1", "g::1",
                                       "1:2:3:4:5:6:7:1.2.3.4", "::1.2.3", "::1.2.3.4:5", "fe80::1%", "[::1", "::1]", "[]"}) {
        INFO(bad);
        CHECK_FALSE(parses(bad));
    }
}

TEST_CASE("ip_address: host names are not addresses", "[net][address]") {
    // Hex-looking names were once taken for addresses (and skipped the TLS host-name check).
    for (const std::string_view name : {"cafe1", "db1.de", "beef", "add.ed", "localhost", "game.test", "a.b.c.d", "dead:beef", "1.2.3.4.example"}) {
        INFO(name);
        CHECK_FALSE(parses(name));
    }
}

TEST_CASE("ip_address: a source is an IPv4 address or an IPv6 /64", "[net][address]") {
    CHECK(ip_address::v4(192, 0, 2, 7).source() == ip_address::v4(192, 0, 2, 7));
    CHECK(ip_address::v4(192, 0, 2, 7).source() != ip_address::v4(192, 0, 2, 8).source());
    const auto a = ip_address::parse("2001:db8:1:2:aaaa::1");
    const auto b = ip_address::parse("2001:db8:1:2:bbbb::9");
    const auto c = ip_address::parse("2001:db8:1:3::1");
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);
    CHECK(a->source() == b->source());
    CHECK(a->source() != c->source());
    CHECK(a->source() == ip_address::parse("2001:db8:1:2::"));
}
