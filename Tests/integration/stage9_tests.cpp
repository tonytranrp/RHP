#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/async.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage9_fixtures {

// fetch(x): x * 10, from a worker thread a little later.
inline Rhp::async<int> fetch(int x) {
    auto [result, done] = Rhp::make_async<int>();
    std::thread{[d = std::move(done), x] {
        std::this_thread::sleep_for(20ms);
        (void)d.complete(x * 10);
    }}.detach();
    return std::move(result);
}

// spawn(): an entity id that the test hands out by hand (g_pending); undone with despawn(id).
inline std::mutex g_mutex;
inline std::vector<Rhp::promise<int>> g_pending;
inline std::vector<int> g_despawned;

inline Rhp::async<int> spawn() {
    auto [result, done] = Rhp::make_async<int>();
    const std::scoped_lock lock{g_mutex};
    g_pending.push_back(std::move(done));
    return std::move(result);
}

inline void despawn(int id) {
    const std::scoped_lock lock{g_mutex};
    g_despawned.push_back(id);
}

inline std::size_t pending_count() {
    const std::scoped_lock lock{g_mutex};
    return g_pending.size();
}

inline std::optional<Rhp::promise<int>> take_pending() {
    const std::scoped_lock lock{g_mutex};
    if (g_pending.empty()) {
        return std::nullopt;
    }
    auto p = std::move(g_pending.front());
    g_pending.erase(g_pending.begin());
    return p;
}

inline std::vector<int> despawned() {
    const std::scoped_lock lock{g_mutex};
    return g_despawned;
}

inline void reset() {
    const std::scoped_lock lock{g_mutex};
    g_pending.clear();
    g_despawned.clear();
}

using test_lib = Rhp::lib<"s9">::fn<"fetch", &fetch>::fn<"spawn", &spawn, Rhp::undo<&despawn>>;

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

struct keys {
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const { return Rhp::security::keyring{{"patch", patch, Rhp::role::kPatch}}; }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as_patch() const { return {"patch", patch}; }
};

// A host pumped on its own thread.
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k) : host_(std::move(ep), k.ring(), k.trusted()) {
        REQUIRE(host_.install<test_lib>());
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~running_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;

private:
    Rhp::host<cfg> host_;
    std::jthread pump_;
};

bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(2ms);
    }
    return true;
}

} // namespace stage9_fixtures

using namespace stage9_fixtures;

TEST_CASE("stage9: a remote exec waits for an async binding completed on a worker thread", "[stage9][async]") {
    reset();
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s9.fetch", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as_patch(), k.signer()};
    const auto r = c.exec<int>("return s9.fetch(4) + s9.fetch(1)");
    REQUIRE(r.has_value());
    CHECK(*r == 50);
}

TEST_CASE("stage9: a client cancel stops a waiting call and its late result is taken back", "[stage9][async]") {
    reset();
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s9.cancel", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as_patch(), k.signer()};
    auto p = c.async().exec("s9.spawn()");
    REQUIRE(eventually([] { return pending_count() == 1; }));
    c.cancel(p.request());
    const auto r = p.get();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kCancelled);
    auto done = take_pending();
    REQUIRE(done.has_value());
    CHECK(done->stop_requested());
    CHECK(done->complete(31));
    CHECK(eventually([] { return despawned() == std::vector<int>{31}; }));
}

TEST_CASE("stage9: a client that disconnects while its call waits leaves nothing behind", "[stage9][async]") {
    reset();
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s9.disconnect", 1);
    running_host host{at, k};
    {
        Rhp::client<cfg> c{at.reversed(), k.as_patch(), k.signer()};
        auto p = c.async().exec("s9.spawn()");
        REQUIRE(eventually([] { return pending_count() == 1; }));
    } // the identity's last session ends: its scripts stop
    auto done = take_pending();
    REQUIRE(done.has_value());
    REQUIRE(eventually([&] { return done->stop_requested(); }));
    (void)done->complete(8);
    CHECK(eventually([] { return despawned() == std::vector<int>{8}; }));
}

TEST_CASE("stage9: an async result kept by a loaded module is reverted remotely", "[stage9][async]") {
    reset();
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s9.revert", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as_patch(), k.signer()};
    auto loading = c.async().load("tests.s9.spawner", "id = s9.spawn()");
    REQUIRE(eventually([] { return pending_count() == 1; }));
    auto done = take_pending();
    REQUIRE(done.has_value());
    CHECK(done->complete(5));
    const auto mod = loading.get();
    REQUIRE(mod.has_value());
    const auto report = c.revert(*mod);
    REQUIRE(report.has_value());
    CHECK(despawned() == std::vector<int>{5});
}
