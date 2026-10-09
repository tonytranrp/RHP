#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/audit/sinks.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/event/hub.hpp>

using namespace Rhp;

namespace {

event::script_executed sample() {
    event::script_executed e;
    e.time = std::chrono::sys_days{std::chrono::year{2026} / 10 / 8} + std::chrono::hours{22} + std::chrono::milliseconds{13'123};
    e.session = session_id{7};
    e.identity = "dev";
    e.granted = role::kAdmin;
    e.op = "load";
    e.module = "low \"grav\"\n";
    e.hash = "ab12";
    e.signer = "dev";
    return e;
}

} // namespace

TEST_CASE("events have names and kinds", "[event]") {
    STATIC_REQUIRE(event::host_event<event::script_executed>);
    STATIC_REQUIRE(event::host_event<event::identity_reverted>);
    STATIC_REQUIRE_FALSE(event::host_event<int>);
    STATIC_REQUIRE(event::kind_of<event::session_opened> == 0);
    STATIC_REQUIRE(event::kind_of<event::identity_reverted> == 5);
    CHECK(event::script_executed::name == "script_executed");
}

TEST_CASE("to_json writes one escaped line", "[event][json]") {
    const std::string line = event::to_json(sample());
    CHECK(line ==
          R"({"event":"script_executed","time":"2026-10-08T22:00:13.123Z","session":7,"identity":"dev","role":"admin","op":"load","module":"low \"grav\"\n","hash":"ab12","signer":"dev","outcome":{"code":"ok"}})");
    event::auth_failed failed;
    failed.peer = "127.0.0.1:5000";
    failed.reason = make_error(errc::kAuth, "bad\tproof\x01", "psk");
    CHECK(event::to_json(failed).ends_with(R"("peer":"127.0.0.1:5000","reason":{"code":"auth","message":"bad\tproof\u0001","where":"psk"}})"));
    CHECK(event::to_json(failed).find('\n') == std::string::npos);
}

TEST_CASE("the hub delivers by kind until the subscription dies", "[event][hub]") {
    auto hub = std::make_shared<event::hub>();
    std::vector<std::string> seen;
    CHECK_FALSE(hub->wants(event::kind_of<event::script_executed>));
    {
        auto scripts = event::subscribe<event::script_executed>(hub, [&](const event::script_executed& e) { seen.push_back("script " + e.op); });
        auto all = event::subscribe_any(hub, [&](const event::any& e) { seen.push_back("any " + std::to_string(e.index())); });
        CHECK(hub->wants(event::kind_of<event::script_executed>));
        CHECK(hub->wants(event::kind_of<event::session_opened>)); // through `all`
        hub->publish(sample());
        hub->publish(event::session_opened{});
        CHECK(seen == std::vector<std::string>{"script load", "any 3", "any 0"});

        // Moving keeps it subscribed; reset() ends it.
        event::subscription moved = std::move(scripts);
        CHECK(moved.active());
        CHECK_FALSE(scripts.active());
        moved.reset();
        hub->publish(sample());
        CHECK(seen.back() == "any 3");
        CHECK(seen.size() == 4);
    }
    hub->publish(sample());
    CHECK(seen.size() == 4); // everything unsubscribed
    CHECK_FALSE(hub->wants(event::hub::kAnyKind));
}

TEST_CASE("a handler may unsubscribe itself; a subscription may outlive its hub", "[event][hub]") {
    auto hub = std::make_shared<event::hub>();
    int calls = 0;
    event::subscription self;
    self = event::subscribe<event::session_closed>(hub, [&](const event::session_closed&) {
        ++calls;
        self.reset();
    });
    hub->publish(event::session_closed{});
    hub->publish(event::session_closed{});
    CHECK(calls == 1);

    auto orphan = event::subscribe_any(hub, [](const event::any&) {});
    hub.reset();
    CHECK_FALSE(orphan.active());
    orphan.reset(); // no hub: nothing to do
}

TEST_CASE("audit sinks write JSON lines", "[audit]") {
    std::ostringstream out;
    const audit::ostream_sink to_stream{out};
    to_stream(sample());
    to_stream(event::any{event::identity_reverted{}});
    const std::string text = out.str();
    CHECK(text.starts_with(R"({"event":"script_executed")"));
    CHECK(text.find("\n{\"event\":\"identity_reverted\"") != std::string::npos);
    CHECK(text.ends_with("}\n"));

    const auto path = (std::filesystem::temp_directory_path() / "rhp_audit_test.log").string();
    std::filesystem::remove(path);
    {
        const audit::file_sink file{path};
        REQUIRE(file.ok());
        const audit::file_sink copy = file; // copies share the file
        file(sample());
        copy(event::any{event::auth_failed{}});
    }
    std::ifstream in{path};
    std::string first;
    std::string second;
    REQUIRE(std::getline(in, first));
    REQUIRE(std::getline(in, second));
    CHECK(first.find("script_executed") != std::string::npos);
    CHECK(second.find("auth_failed") != std::string::npos);
    in.close();
    std::filesystem::remove(path);

    const audit::file_sink nowhere{(std::filesystem::temp_directory_path() / "no_such_dir_rhp" / "x.log").string()};
    CHECK(nowhere.ok().error().code == errc::kInvalidArgument);
    nowhere(sample()); // dropped, no crash
}

TEST_CASE("to_json keeps valid UTF-8 and replaces invalid bytes", "[event][json]") {
    event::script_executed e = sample();
    e.module = "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x99\x82"; // é € 🙂
    CHECK(event::to_json(e).find("\"module\":\"caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x99\x82\"") != std::string::npos);
    e.module = std::string{"a\xFF"
                           "b\xC3"
                           "c\xED\xA0\x80"
                           "d\xC0\xAF"}; // stray byte, truncated, surrogate, overlong
    const std::string line = event::to_json(e);
    const std::string r = "\xEF\xBF\xBD"; // U+FFFD
    CHECK(line.find("\"module\":\"a" + r + "b" + r + "c" + r + r + r + "d" + r + r + "\"") != std::string::npos);
}
