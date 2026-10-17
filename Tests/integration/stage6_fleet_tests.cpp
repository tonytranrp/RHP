#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/rhp.hpp>

namespace stage6_fleet_fixtures {

std::atomic<int> applied{0};
int apply(int by) {
    applied.fetch_add(by);
    return by;
}
void unapply(int by) {
    applied.fetch_sub(by);
}
using lib = Rhp::lib<"fleet6">::fn<"apply", &apply, Rhp::undo<&unapply>>;

struct keys {
    Rhp::security::key secret = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::keyring ring() const { return {{"patch", secret, Rhp::role::kPatch}}; }
    Rhp::security::psk_identity identity() const { return {"patch", secret}; }
    Rhp::security::trusted_signers trust() const { return {{"dev", developer.public_key()}}; }
    Rhp::security::signing_key signing() const { return {"dev", developer}; }
};

using cfg = Rhp::config<>::logger<Rhp::core::null_logger>;
using zero_cfg = cfg::io<Rhp::exec::zero_threads>;

// A host on 127.0.0.1 (port 0) whose pump runs on its own thread.
struct running_host {
    Rhp::host<cfg> host;
    std::jthread pump;
    explicit running_host(const keys& key) : host(Rhp::endpoint::listen("127.0.0.1", 0), key.ring(), key.trust()) {
        REQUIRE(host.port());
        REQUIRE(host.install<lib>());
        pump = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host.pump();
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }};
    }
    ~running_host() {
        pump.request_stop();
        pump.join();
    }
    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;
};

// A host nobody pumps: its network thread authenticates sessions, but no request ever runs.
struct stalled_host {
    Rhp::host<cfg> host;
    explicit stalled_host(const keys& key) : host(Rhp::endpoint::listen("127.0.0.1", 0), key.ring(), key.trust()) { REQUIRE(host.port()); }
};

Rhp::net::service_record record_for(std::string name, Rhp::result<std::uint16_t> port) {
    REQUIRE(port);
    Rhp::net::service_record record;
    record.name = std::move(name);
    record.address = "127.0.0.1";
    record.port = *port;
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    return record;
}

// Which threads the members' on_output ran on: the threads that ran their networks.
struct output_threads {
    std::mutex mutex;
    std::set<std::thread::id> ids;
    std::size_t lines = 0;

    Rhp::client_options options() {
        Rhp::client_options o;
        o.on_output = [this](std::uint64_t, std::string_view) {
            const std::scoped_lock lock{mutex};
            ids.insert(std::this_thread::get_id());
            ++lines;
        };
        return o;
    }
};

template <class T>
void require_ok(const Rhp::host_result<T>& entry) {
    const auto diagnostic = entry.outcome ? std::string{"ok"} : std::format("{}: {}", entry.host.name, entry.outcome.error());
    INFO(diagnostic);
    REQUIRE(entry.outcome);
}

constexpr std::string_view kAdder = "fleet6.apply(1); return { add = function(x, y) return x + y end, pair = function() return 1, 2 end }";

} // namespace stage6_fleet_fixtures

using namespace stage6_fleet_fixtures;

TEST_CASE("stage6 fleet: load and call reach every member", "[integration][stage6][fleet]") {
    keys key;
    running_host a{key};
    running_host b{key};
    {
        Rhp::fleet<cfg> fleet{key.identity(), key.signing()};
        REQUIRE(fleet.add(record_for("a", a.host.port())));
        REQUIRE(fleet.add(record_for("b", b.host.port())));

        auto loaded = fleet.load("tests.fleet6.adder", kAdder);
        REQUIRE(loaded.size() == 2);
        for (const auto& entry : loaded) {
            require_ok(entry);
            CHECK(entry.outcome->valid());
        }
        CHECK(loaded.front().host.name == "a");
        CHECK(loaded.back().host.name == "b");
        CHECK(applied.load() == 2);

        auto sums = fleet.call<int>("tests.fleet6.adder", "add", 40, 2);
        REQUIRE(sums.size() == 2);
        for (const auto& entry : sums) {
            require_ok(entry);
            CHECK(*entry.outcome == 42);
        }

        const Rhp::value args[] = {Rhp::value{5}, Rhp::value{6}};
        auto spans = fleet.call<int>("tests.fleet6.adder", "add", std::span<const Rhp::value>{args});
        REQUIRE(spans.size() == 2);
        for (const auto& entry : spans) {
            require_ok(entry);
            CHECK(*entry.outcome == 11);
        }

        auto pairs = fleet.call("tests.fleet6.adder", "pair");
        REQUIRE(pairs.size() == 2);
        for (const auto& entry : pairs) {
            require_ok(entry);
            CHECK(*entry.outcome == Rhp::value_list{Rhp::value{1}, Rhp::value{2}});
        }

        // A member without the module answers for itself; the others still answer.
        running_host c{key};
        REQUIRE(fleet.add(record_for("c", c.host.port())));
        auto mixed = fleet.call<int>("tests.fleet6.adder", "add", 1, 1);
        REQUIRE(mixed.size() == 3);
        require_ok(mixed[0]);
        require_ok(mixed[1]);
        CHECK(*mixed[0].outcome == 2);
        CHECK(*mixed[1].outcome == 2);
        REQUIRE_FALSE(mixed[2].outcome);
        CHECK(mixed[2].outcome.error().code == Rhp::errc::kNotFound);
    }
    // The fleet's sessions were the identity's last: both hosts revert the modules' effects.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (applied.load() != 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    CHECK(applied.load() == 0);
}

TEST_CASE("stage6 fleet: load is signed and calls need no signature", "[integration][stage6][fleet]") {
    keys key;
    running_host a{key};
    running_host b{key};
    Rhp::fleet<cfg> signer{key.identity(), key.signing()};
    REQUIRE(signer.add(record_for("a", a.host.port())));
    REQUIRE(signer.add(record_for("b", b.host.port())));
    for (const auto& entry : signer.load("tests.fleet6.signed", "return { get = function() return 7 end }")) {
        require_ok(entry);
    }

    // The same identity without a signing key: code is refused by every host, loaded code still runs.
    Rhp::fleet<cfg> viewer{key.identity()};
    REQUIRE(viewer.add(record_for("a", a.host.port())));
    REQUIRE(viewer.add(record_for("b", b.host.port())));
    auto refused = viewer.load("tests.fleet6.unsigned", "return {}");
    REQUIRE(refused.size() == 2);
    for (const auto& entry : refused) {
        REQUIRE_FALSE(entry.outcome);
        CHECK(entry.outcome.error().code == Rhp::errc::kBadSignature);
    }
    auto called = viewer.call<int>("tests.fleet6.signed", "get");
    REQUIRE(called.size() == 2);
    for (const auto& entry : called) {
        require_ok(entry);
        CHECK(*entry.outcome == 7);
    }
}

TEST_CASE("stage6 fleet: load and call share one deadline per broadcast", "[integration][stage6][fleet]") {
    keys key;
    running_host live{key};
    stalled_host first{key};
    stalled_host second{key};
    Rhp::fleet_options options;
    options.timeout = std::chrono::milliseconds{1500};
    Rhp::fleet<cfg> fleet{key.identity(), key.signing(), options};
    REQUIRE(fleet.add(record_for("live", live.host.port())));
    REQUIRE(fleet.add(record_for("first", first.host.port())));
    REQUIRE(fleet.add(record_for("second", second.host.port())));

    const auto started = std::chrono::steady_clock::now();
    auto loaded = fleet.load("tests.fleet6.deadline", "return { get = function() return 9 end }");
    const auto took = std::chrono::steady_clock::now() - started;
    REQUIRE(loaded.size() == 3);
    require_ok(loaded[0]);
    for (std::size_t i = 1; i < loaded.size(); ++i) {
        REQUIRE_FALSE(loaded[i].outcome);
        CHECK(loaded[i].outcome.error().code == Rhp::errc::kTimeout);
    }
    // One deadline for the whole broadcast, not one per stalled host.
    CHECK(took >= std::chrono::milliseconds{1400});
    CHECK(took < std::chrono::milliseconds{2900});

    auto called = fleet.call<int>("tests.fleet6.deadline", "get");
    REQUIRE(called.size() == 3);
    require_ok(called[0]);
    CHECK(*called[0].outcome == 9);
    CHECK(called[1].outcome.error().code == Rhp::errc::kTimeout);
    CHECK(called[2].outcome.error().code == Rhp::errc::kTimeout);
}

TEST_CASE("stage6 fleet: every member shares one network thread", "[integration][stage6][fleet]") {
    keys key;
    running_host a{key};
    running_host b{key};
    running_host c{key};
    output_threads seen;
    Rhp::fleet_options options;
    options.client = seen.options();
    Rhp::fleet<cfg> fleet{key.identity(), key.signing(), options};
    REQUIRE(fleet.add(record_for("a", a.host.port())));
    REQUIRE(fleet.add(record_for("b", b.host.port())));
    REQUIRE(fleet.add(record_for("c", c.host.port())));
    for (int round = 0; round < 2; ++round) {
        auto printed = fleet.exec<int>("print('fleet6') return 6");
        REQUIRE(printed.size() == 3);
        for (const auto& entry : printed) {
            require_ok(entry);
            CHECK(*entry.outcome == 6);
        }
    }
    const std::scoped_lock lock{seen.mutex};
    CHECK(seen.lines == 6);
    // One I/O thread for the fleet (a client per member would have run three), not the caller's.
    REQUIRE(seen.ids.size() == 1);
    CHECK(*seen.ids.begin() != std::this_thread::get_id());
}

TEST_CASE("stage6 fleet: a zero-thread fleet runs every member on the calling thread", "[integration][stage6][fleet]") {
    keys key;
    running_host a{key};
    running_host b{key};
    output_threads seen;
    Rhp::fleet_options options;
    options.client = seen.options();
    Rhp::fleet<zero_cfg> fleet{key.identity(), key.signing(), options};
    REQUIRE(fleet.add(record_for("a", a.host.port())));
    REQUIRE(fleet.add(record_for("b", b.host.port())));

    auto printed = fleet.exec<int>("print('fleet6') return 6");
    REQUIRE(printed.size() == 2);
    for (const auto& entry : printed) {
        require_ok(entry);
    }
    for (const auto& entry : fleet.load("tests.fleet6.zero", kAdder)) {
        require_ok(entry);
    }
    // Idle: poll() keeps the sessions served (pings) between broadcasts.
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds{300};
    while (std::chrono::steady_clock::now() < until) {
        fleet.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    auto sums = fleet.call<int>("tests.fleet6.zero", "add", 20, 22);
    REQUIRE(sums.size() == 2);
    for (const auto& entry : sums) {
        require_ok(entry);
        CHECK(*entry.outcome == 42);
    }
    const std::scoped_lock lock{seen.mutex};
    CHECK(seen.lines == 2);
    REQUIRE(seen.ids.size() == 1);
    CHECK(*seen.ids.begin() == std::this_thread::get_id());
}
