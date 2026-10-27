// Stage 13 (AL4): per-identity request rate and pump budget on a host.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>
#include <rhp_test/script_support.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using rhp_test::code_of;

namespace stage13_limits_fixtures {

int g_runs = 0;      // requests that ran (pump thread)
std::string g_turns; // who ran, in order: 'a' (admin) or 'p' (patch) (pump thread)

int run() {
    return ++g_runs;
}

void turn(std::string_view who) {
    g_turns += who;
}

using s13l_lib = Rhp::lib<"s13l">::fn<"run", &run>::fn<"turn", &turn>;

// The host's clock (config<>::clock): it moves only when a test moves it.
inline std::atomic<std::int64_t> g_clock_ms{0};
struct manual_clock {
    [[nodiscard]] std::chrono::steady_clock::time_point now() const noexcept {
        return std::chrono::steady_clock::time_point{std::chrono::hours{1}} + std::chrono::milliseconds{g_clock_ms.load()};
    }
};

using loop_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>::clock<manual_clock>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"patch", patch, Rhp::role::kPatch}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key dev() const { return {"dev", developer}; }
};

// Pumps `host` on another thread while it lives.
template <class Host>
class pumping {
public:
    explicit pumping(Host& host)
        : thread_([&host](const std::stop_token& stop) {
              while (!stop.stop_requested()) {
                  host.pump();
                  std::this_thread::sleep_for(1ms);
              }
          }) {}

private:
    std::jthread thread_;
};

// The order limits.pump_requests starts `turns` in within one pump(): rounds of one request per
// identity, the identity of `turns.front()` first.
[[nodiscard]] std::string in_turn(std::string_view turns) {
    const char first = turns.front();
    const char other = first == 'a' ? 'p' : 'a';
    const auto mine = static_cast<std::size_t>(std::ranges::count(turns, first));
    const auto theirs = static_cast<std::size_t>(std::ranges::count(turns, other));
    std::string out;
    for (std::size_t round = 0; round < std::max(mine, theirs); ++round) {
        if (round < mine) {
            out += first;
        }
        if (round < theirs) {
            out += other;
        }
    }
    return out;
}

} // namespace stage13_limits_fixtures

using namespace stage13_limits_fixtures;

TEST_CASE("stage13: limits.request_rate refuses beyond the rate and refills with the host's clock", "[host][limits][stage13]") {
    using rated_cfg = loop_cfg::limits<Rhp::limits{.request_rate = 3}>;
    const keys k;
    const auto at = Rhp::endpoint::listen("s13l.rate", 1);
    Rhp::host<rated_cfg> host{at, k.ring(), k.trusted()};
    REQUIRE(host.install<s13l_lib>());
    std::atomic<std::size_t> received{0};
    REQUIRE(host.on_blob(
        "s13l",
        [&](const Rhp::blob_view& b) -> Rhp::result<void> {
            received = b.bytes.size();
            return {};
        },
        Rhp::role::kPatch));
    std::mutex mutex;
    std::vector<Rhp::error> refused; // audit records of requests that failed
    const auto audit = host.on<Rhp::event::script_executed>([&](const Rhp::event::script_executed& e) {
        if (e.outcome.code != errc::kOk) {
            const std::scoped_lock lock{mutex};
            refused.push_back(e.outcome);
        }
    });
    const pumping pump{host};
    Rhp::client<rated_cfg> c{at.reversed(), {"patch", k.patch}, k.dev()};
    REQUIRE(c.connect());
    g_runs = 0;

    // The bucket holds three: a burst of three runs, the fourth is answered without running.
    for (int i = 1; i <= 3; ++i) {
        CHECK(c.exec<int>("return s13l.run()") == i);
    }
    const auto over = c.exec<int>("return s13l.run()");
    REQUIRE(code_of(over) == errc::kLimitExceeded);
    CHECK(over.error().message.find("limits.request_rate") != std::string::npos);
    CHECK(g_runs == 3);
    CHECK(rhp_test::eventually([&] {
        const std::scoped_lock lock{mutex};
        return refused.size() == 1 && refused.front().code == errc::kLimitExceeded;
    }));

    // A third of a second on the host's clock gives one token back; a second, the whole bucket.
    g_clock_ms += 334;
    CHECK(c.exec<int>("return s13l.run()") == 4);
    CHECK(code_of(c.exec<int>("return s13l.run()")) == errc::kLimitExceeded);
    g_clock_ms += 1'000;
    for (int i = 5; i <= 7; ++i) {
        CHECK(c.exec<int>("return s13l.run()") == i);
    }
    CHECK(code_of(c.exec<int>("return s13l.run()")) == errc::kLimitExceeded);

    // Each identity has a bucket of its own.
    Rhp::client<rated_cfg> admin{at.reversed(), {"admin", k.admin}, k.dev()};
    REQUIRE(admin.connect());
    CHECK(admin.exec<int>("return s13l.run()") == 8);

    // A blob takes one token, however many chunks it comes in.
    g_clock_ms += 1'000;
    Rhp::client_options small_chunks;
    small_chunks.blob_chunk = 16;
    Rhp::client<rated_cfg> chunks{at.reversed(), {"patch", k.patch}, k.dev(), small_chunks};
    REQUIRE(chunks.connect());
    const std::vector<std::byte> blob(100, std::byte{7});
    REQUIRE(chunks.blob("s13l", blob));
    CHECK(received.load() == blob.size());
    CHECK(c.exec<int>("return s13l.run()") == 9);
    CHECK(c.exec<int>("return s13l.run()") == 10);
    CHECK(code_of(c.exec<int>("return s13l.run()")) == errc::kLimitExceeded);
}

TEST_CASE("stage13: without limits.request_rate a frozen clock refuses nothing", "[host][limits][stage13]") {
    const keys k;
    const auto at = Rhp::endpoint::listen("s13l.unrated", 1);
    Rhp::host<loop_cfg> host{at, k.ring(), k.trusted()};
    REQUIRE(host.install<s13l_lib>());
    const pumping pump{host};
    Rhp::client<loop_cfg> c{at.reversed(), {"patch", k.patch}, k.dev()};
    REQUIRE(c.connect());
    g_runs = 0;
    for (int i = 1; i <= 50; ++i) {
        REQUIRE(c.exec<int>("return s13l.run()") == i);
    }
}

TEST_CASE("stage13: limits.pump_requests serves identities in turn", "[host][limits][stage13]") {
    constexpr std::uint32_t kBudget = 2;
    using budget_cfg = loop_cfg::limits<Rhp::limits{.pump_requests = kBudget}>;
    const keys k;
    const auto at = Rhp::endpoint::listen("s13l.turns", 1);
    Rhp::host<budget_cfg> host{at, k.ring(), k.trusted()};
    REQUIRE(host.install<s13l_lib>());
    Rhp::client<budget_cfg> admin{at.reversed(), {"admin", k.admin}, k.dev()};
    Rhp::client<budget_cfg> patch{at.reversed(), {"patch", k.patch}, k.dev()};
    {
        const pumping pump{host};
        REQUIRE(admin.connect());
        REQUIRE(patch.connect());
        REQUIRE(admin.exec("return 1")); // both identities have their sandbox
        REQUIRE(patch.exec("return 1"));
    }

    // The admin floods, the patch identity sends a few; this thread pumps and looks after each pump.
    constexpr std::size_t kFlood = 18;
    constexpr std::size_t kFew = 6;
    std::atomic<std::size_t> answered{0};
    std::atomic<std::size_t> failed{0};
    const auto done = [&](const Rhp::result<Rhp::value_list>& r) {
        if (!r) {
            ++failed;
        }
        ++answered;
    };
    for (std::size_t i = 0; i < kFlood; ++i) {
        admin.exec_async("s13l.turn('a')", done);
    }
    for (std::size_t i = 0; i < kFew; ++i) {
        patch.exec_async("s13l.turn('p')", done);
    }
    g_turns.clear();
    std::vector<std::string> pumps; // what each pump started
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (g_turns.size() < kFlood + kFew && std::chrono::steady_clock::now() < deadline) {
        const std::size_t before = g_turns.size();
        host.pump();
        pumps.push_back(g_turns.substr(before));
        std::this_thread::sleep_for(2ms);
    }
    REQUIRE(g_turns.size() == kFlood + kFew);
    CHECK(rhp_test::eventually([&] { return answered.load() == kFlood + kFew; }));
    CHECK(failed.load() == 0);

    const auto both = [](const std::string& s) { return s.contains('a') && s.contains('p'); };
    bool alternated = false; // two pumps in a row started requests of both identities
    for (std::size_t i = 0; i < pumps.size(); ++i) {
        const std::string& p = pumps[i];
        if (p.empty()) {
            continue;
        }
        INFO("pump " << i << " started " << p);
        CHECK(std::cmp_less_equal(std::ranges::count(p, 'a'), kBudget));
        CHECK(std::cmp_less_equal(std::ranges::count(p, 'p'), kBudget));
        CHECK(p == in_turn(p)); // one request per identity per round
        if (i > 0 && both(p) && both(pumps[i - 1])) {
            CHECK(p.front() != pumps[i - 1].front()); // the other identity goes first next time
            alternated = true;
        }
    }
    CHECK(alternated);
}
