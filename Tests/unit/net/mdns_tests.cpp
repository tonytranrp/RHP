#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/net/mdns/detail/dns.hpp>
#include <rhp/net/mdns/mdns.hpp>
#include <rhp/wire/ops.hpp>

namespace {

Rhp::net::service_record service(std::string name, unsigned short port) {
    Rhp::net::service_record record;
    record.name = std::move(name);
    record.host = record.name + ".rhp.local";
    record.address = "127.0.0.1";
    record.port = port;
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    record.platform = "test";
    record.app = "rhp.mdns.tests";
    record.build = "test";
    return record;
}

} // namespace

TEST_CASE("mdns: DNS records round trip and malformed names are refused", "[net][mdns]") {
    auto record = service("dns-parser", 7777);
    auto bytes = Rhp::net::detail::dns_service_packet(record, 120);
    REQUIRE(bytes);
    auto parsed = Rhp::net::detail::read_dns(bytes->view());
    REQUIRE(parsed);
    CHECK(parsed->response);
    REQUIRE(parsed->records.size() == 4);
    CHECK(parsed->records[0].target == "dns-parser._rhp._tcp.local");
    CHECK(parsed->records[1].port == 7777);
    CHECK(parsed->records[3].address == "127.0.0.1");
    for (std::size_t n = 0; n < bytes->size(); ++n) {
        CHECK_FALSE(Rhp::net::detail::read_dns(bytes->view().first(n)));
    }
    // An answer to a query: the asked record in the answer section, the rest additional.
    const std::vector<std::pair<std::string, std::uint16_t>> asked{{"dns-parser._rhp._tcp.local", static_cast<std::uint16_t>(Rhp::net::detail::rr_type::kSrv)}};
    auto answer = Rhp::net::detail::dns_service_packet(record, 120, false, asked);
    REQUIRE(answer);
    const auto counts = answer->view().subspan(6, 6);
    CHECK(counts[1] == std::byte{1}); // answers
    CHECK(counts[5] == std::byte{3}); // additional
    auto answered = Rhp::net::detail::read_dns(answer->view());
    REQUIRE(answered);
    REQUIRE(answered->records.size() == 4);
    CHECK(answered->records[0].port == 7777);
    CHECK(answered->records[1].target == "dns-parser._rhp._tcp.local");
    record.host = std::string(64, 'x') + ".local";
    CHECK_FALSE(Rhp::net::detail::dns_service_packet(record, 120));
    record.host = "a..local";
    CHECK_FALSE(Rhp::net::detail::dns_service_packet(record, 120));
    auto query = Rhp::net::detail::dns_query("_rhp._tcp");
    query.mutable_view()[12] = std::byte{0xc0};
    query.mutable_view()[13] = std::byte{12};
    CHECK_FALSE(Rhp::net::detail::read_dns(query.view()));
}

TEST_CASE("mdns: the wire provider keeps independent hosts and their updates", "[net][mdns][multicast]") {
    Rhp::net::io_context a;
    Rhp::net::io_context b;
    Rhp::net::io_context browsing;
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto first = service("first-" + unique, 10001);
    auto second = service("second-" + unique, 10002);
    auto advertised_a = Rhp::net::mdns_wire::advertise(a, first);
    auto advertised_b = Rhp::net::mdns_wire::advertise(b, second);
    REQUIRE(advertised_a);
    REQUIRE(advertised_b);
    Rhp::net::browse_options filter;
    filter.app = first.app;
    filter.build = first.build;
    auto browser = Rhp::net::mdns_wire::start_browse(browsing, filter);
    REQUIRE(browser);
    REQUIRE(rhp_test::poll_until({&a, &b, &browsing}, [&] {
        auto found = (*browser)->services();
        return found && found->size() == 2;
    }));
    first.host.clear(); // host.advertise supplies an unresolved record on updates too
    first.libs = {"game"};
    REQUIRE((*advertised_a)->update(first));
    REQUIRE(rhp_test::poll_until({&a, &b, &browsing}, [&] {
        auto found = (*browser)->services();
        return found && std::ranges::any_of(*found, [&](const auto& r) { return r.name == first.name && r.libs == first.libs; });
    }));
    advertised_a->reset();
    REQUIRE(rhp_test::poll_until({&a, &b, &browsing}, [&] {
        auto found = (*browser)->services();
        return found && found->size() == 1 && found->front().name == second.name;
    }));
    CHECK((*advertised_b)->status());
}

TEST_CASE("mdns: the native provider advertises and resolves metadata", "[net][mdns][multicast]") {
    Rhp::net::io_context io;
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto record = service("native-" + unique, 10003);
    SECTION("constrained listener address") {}
    SECTION("IPv4 wildcard listener") {
        record.address = "0.0.0.0";
    }
    // Let the provider choose its service hostname while preserving the listener address.
    record.host.clear();
    auto advertised = Rhp::net::mdns::advertise(io, record);
    REQUIRE(advertised);
    Rhp::net::browse_options filter;
    filter.app = record.app;
    auto browser = Rhp::net::mdns::start_browse(io, filter);
    REQUIRE(browser);
    const bool resolved = rhp_test::poll_until({&io}, [&] {
        auto found = (*browser)->services();
        return found && std::ranges::any_of(*found, [&](const auto& r) { return r.name == record.name && r.port == record.port; }); }, std::chrono::seconds{15});
    const auto status = (*advertised)->status();
    const auto diagnostic = status ? std::string{"registration ok"} : std::format("{}", status.error());
    INFO(diagnostic);
    REQUIRE(resolved);
    REQUIRE(status);
    auto found = (*browser)->services();
    REQUIRE(found);
    const auto own = std::ranges::find_if(*found, [&](const auto& r) { return r.name == record.name; });
    REQUIRE(own != found->end());
    if (record.address == "127.0.0.1") {
        CHECK(own->address == record.address);
    } else {
        CHECK(own->address != "0.0.0.0");
        CHECK_FALSE(own->address.empty());
    }
    record.build = "updated";
    REQUIRE((*advertised)->update(record));
    REQUIRE(rhp_test::poll_until({&io}, [&] {
        auto found = (*browser)->services();
        return found && std::ranges::any_of(*found, [&](const auto& r) { return r.name == record.name && r.build == "updated"; }); }, std::chrono::seconds{15}));
    CHECK((*advertised)->status());
}

TEST_CASE("mdns: a second host with the same name loses the conflict", "[net][mdns][multicast]") {
    Rhp::net::io_context io;
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto record = service("conflict-" + unique, 10004);
    auto first = Rhp::net::mdns_wire::advertise(io, record);
    REQUIRE(first);
    rhp_test::poll_for({&io}, std::chrono::milliseconds{1100});
    REQUIRE((*first)->status());
    record.app = "different-metadata";
    auto second = Rhp::net::mdns_wire::advertise(io, record);
    REQUIRE(second);
    REQUIRE(rhp_test::poll_until({&io}, [&] { return !(*second)->status(); }));
    CHECK((*first)->status());
    CHECK((*second)->status().error().code == Rhp::errc::kAlreadyLoaded);
}
