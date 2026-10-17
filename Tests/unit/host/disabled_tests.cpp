#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/client/fleet.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/host/host.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

namespace host_disabled_fixtures {

int g_value = 0;
using test_lib = Rhp::lib<"dtest">::var<"value", &g_value>;
using cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

} // namespace host_disabled_fixtures

using namespace host_disabled_fixtures;

TEST_CASE("disabled: the host never listens and reports kDisabled", "[host][disabled]") {
    Rhp::host<cfg> host{Rhp::endpoint::listen("127.0.0.1", 7777), Rhp::security::keyring{}};
    CHECK(host.port().error().code == Rhp::errc::kDisabled);
    CHECK(host.gateway_port().error().code == Rhp::errc::kDisabled);
    CHECK(host.advertise({}).error().code == Rhp::errc::kDisabled);
    CHECK(host.discovery_status().error().code == Rhp::errc::kDisabled);
    CHECK(host.install<test_lib>().error().code == Rhp::errc::kDisabled);
    host.pump();
    CHECK(host.sessions() == 0);
    CHECK(host.identities() == 0);
}

TEST_CASE("disabled: the client reports kDisabled for every call", "[client][disabled]") {
    auto k = Rhp::security::key::generate();
    REQUIRE(k);
    Rhp::client<cfg> c{Rhp::endpoint::dial("127.0.0.1", 7777), Rhp::security::psk_identity{"dev", *k}};
    CHECK(c.connect().error().code == Rhp::errc::kDisabled);
    CHECK(c.exec("return 1").error().code == Rhp::errc::kDisabled);
    CHECK(c.load("m", "return {}").error().code == Rhp::errc::kDisabled);
    CHECK(c.list().error().code == Rhp::errc::kDisabled);
    c.cancel();
    CHECK_FALSE(c.connected());
}

TEST_CASE("disabled: fleet never discovers or executes remotely", "[client][disabled]") {
    auto key = Rhp::security::key::generate();
    REQUIRE(key);
    Rhp::fleet<cfg> group{Rhp::security::psk_identity{"dev", *key}};
    CHECK(group.discover().error().code == Rhp::errc::kDisabled);
    Rhp::net::service_record record;
    record.name = "disabled";
    record.address = "127.0.0.1";
    record.port = 7777;
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    REQUIRE(group.add(record));
    auto results = group.exec<int>("return 42");
    REQUIRE(results.size() == 1);
    CHECK(results.front().outcome.error().code == Rhp::errc::kDisabled);
    auto loaded = group.load("m", "return {}");
    REQUIRE(loaded.size() == 1);
    CHECK(loaded.front().outcome.error().code == Rhp::errc::kDisabled);
    auto called = group.call<int>("m", "f", 1, 2);
    REQUIRE(called.size() == 1);
    CHECK(called.front().outcome.error().code == Rhp::errc::kDisabled);
    group.poll();
    group.clear();
    CHECK(group.size() == 0);
}
