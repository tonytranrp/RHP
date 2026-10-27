#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/script_support.hpp>

#include <rhp/core/async.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace async_tests_fixtures {

// Every pending call, in call order: what it was given and how to complete it.
struct int_call {
    int arg = 0;
    Rhp::promise<int> done;
};

inline std::vector<int_call> g_ints;
inline std::vector<Rhp::promise<void>> g_voids;
inline std::vector<Rhp::promise<std::tuple<int, std::string>>> g_pairs;
inline std::vector<int> g_despawned;
inline std::vector<int> g_unset;
inline int g_throws = 0;

inline void reset() {
    g_ints.clear();
    g_voids.clear();
    g_pairs.clear();
    g_despawned.clear();
    g_unset.clear();
    g_throws = 0;
}

inline Rhp::async<int> later(int x) {
    auto [result, done] = Rhp::make_async<int>();
    g_ints.push_back(int_call{x, std::move(done)});
    return std::move(result);
}

inline Rhp::async<int> ready(int x) {
    return Rhp::async<int>::completed(x * 2);
}

inline Rhp::async<int> missing(int) {
    return Rhp::async<int>::completed(Rhp::fail(errc::kNotFound, "no such thing"));
}

// spawn(kind) -> entity id, later; undone with despawn(id).
inline Rhp::async<int> spawn(int kind) {
    return later(kind);
}

inline void despawn(int id) {
    g_despawned.push_back(id);
}

// set(v): done later; undone with unset(v) (the undo takes the arguments).
inline Rhp::async<void> set(int v) {
    auto [result, done] = Rhp::make_async<void>();
    (void)v;
    g_voids.push_back(std::move(done));
    return std::move(result);
}

inline void unset(int v) {
    g_unset.push_back(v);
}

inline Rhp::async<void> boom() {
    auto [result, done] = Rhp::make_async<void>();
    g_voids.push_back(std::move(done));
    return std::move(result);
}

inline Rhp::async<int> throws(int) {
    ++g_throws;
    throw std::runtime_error{"no worker free"};
}

inline Rhp::async<std::tuple<int, std::string>> pair() {
    auto [result, done] = Rhp::make_async<std::tuple<int, std::string>>();
    g_pairs.push_back(std::move(done));
    return std::move(result);
}

inline Rhp::async<std::string> echo_later(std::string text) {
    auto [result, done] = Rhp::make_async<std::string>();
    std::thread{[d = std::move(done), t = std::move(text)] {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
        (void)d.complete(t + "!");
    }}.detach();
    return std::move(result);
}

using aio_lib = Rhp::lib<"aio">::fn<"later", &later>::fn<"ready", &ready>::fn<"missing", &missing>::fn<"spawn", &spawn, Rhp::undo<&despawn>>::fn<"set", &set, Rhp::undo<&unset>>::fn<"boom", &boom, Rhp::irreversible>::fn<"throws", &throws>::fn<"pair", &pair>::fn<"echo", &echo_later>;

} // namespace async_tests_fixtures

namespace {

namespace fx = async_tests_fixtures;

using rhp_test::manual_clock;

struct capture {
    std::vector<std::string> lines;
    std::map<Rhp::request_id, Rhp::result<value_list>> results;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture& out, Rhp::limits limits = {}, std::shared_ptr<manual_clock> clock = {}) {
    fx::reset();
    sandbox_options options;
    options.limits = limits;
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_result = [&out](Rhp::request_id id, const Rhp::result<value_list>& r) { out.results.insert_or_assign(id, r); };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    if (clock) {
        options.clock = [clock] { return clock->now; };
    }
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::aio_lib>());
    return box;
}

std::optional<Rhp::result<value_list>> result_of(const capture& out, Rhp::request_id id) {
    if (const auto it = out.results.find(id); it != out.results.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string message_of(const Rhp::result<value_list>& r, std::size_t i) {
    if (!r || i >= r->size()) {
        return "<none>";
    }
    const auto* s = r->at(i).get_if<std::string>();
    return s != nullptr ? *s : "<not a string>";
}

// Pumps until `id` has a result (or the deadline passes).
void pump_until(sandbox& box, const capture& out, Rhp::request_id id) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (!out.results.contains(id) && std::chrono::steady_clock::now() < deadline) {
        box.pump();
        std::this_thread::sleep_for(std::chrono::microseconds{200});
    }
}

} // namespace

TEST_CASE("an async binding suspends the script until its result arrives", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto run = box.exec("local v = aio.later(5) return v + 1");
    REQUIRE(run.has_value());
    CHECK(run->empty()); // suspended: the result goes to on_result
    const Rhp::request_id request = box.last_request();
    CHECK(box.pending(request));
    REQUIRE(fx::g_ints.size() == 1);
    CHECK(fx::g_ints[0].arg == 5);
    box.pump();
    box.pump();
    CHECK(box.pending(request)); // nothing arrived: still waiting
    CHECK(box.stats().async_waiting == 1);
    CHECK(fx::g_ints[0].done.complete(10));
    CHECK(box.pending(request)); // woken only by pump()
    box.pump();
    CHECK_FALSE(box.pending(request));
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK(**r == value_list{Rhp::value{11}});
    CHECK(box.stats().async_waiting == 0);
}

TEST_CASE("a ready async result returns without suspending", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto run = box.exec("return aio.ready(4)");
    REQUIRE(run.has_value());
    CHECK(*run == value_list{Rhp::value{8}});
    CHECK(box.suspended() == 0);
}

TEST_CASE("an async error is raised at the call site and pcall catches it", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto now = box.exec("local ok, err = pcall(aio.missing, 1) return ok, tostring(err)");
    REQUIRE(now.has_value());
    CHECK((*now)[0] == Rhp::value{false});
    CHECK(message_of(*now, 1).find("no such thing") != std::string::npos);
    CHECK(message_of(*now, 1).find("aio.missing") != std::string::npos);

    REQUIRE(box.exec("local ok, err = pcall(aio.later, 2) return ok, tostring(err)"));
    const Rhp::request_id request = box.last_request();
    REQUIRE(fx::g_ints.size() == 1);
    CHECK(fx::g_ints[0].done.complete(Rhp::fail(errc::kOutOfRange, "too far")));
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((**r)[0] == Rhp::value{false});
    CHECK(message_of(**r, 1).find("too far") != std::string::npos);
}

TEST_CASE("an uncaught async error fails the request with its code", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("return aio.later(1)"));
    const Rhp::request_id request = box.last_request();
    CHECK(fx::g_ints[0].done.complete(Rhp::fail(errc::kOutOfRange, "too far")));
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->has_value());
    CHECK(r->error().code == errc::kOutOfRange);
}

TEST_CASE("an async binding that throws fails before the script waits", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("return aio.throws(1)");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kRuntime);
    CHECK(r.error().message.find("no worker free") != std::string::npos);
    CHECK(fx::g_throws == 1);
    CHECK(box.suspended() == 0);
}

TEST_CASE("an async result is journaled and reverted with its module", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.spawner", "id = aio.spawn(3)");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->state == Rhp::script::module_state::kLoading);
    REQUIRE(fx::g_ints.size() == 1);
    CHECK(fx::g_ints[0].done.complete(77));
    box.pump();
    CHECK(box.status(*mod)->state == Rhp::script::module_state::kActive);
    const auto report = box.revert(*mod);
    REQUIRE(report.has_value());
    CHECK(report->undone == 1);
    CHECK(fx::g_despawned == std::vector<int>{77});
}

TEST_CASE("an undo fed with the arguments gets copies kept across the wait", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.setter", "aio.set(41)");
    REQUIRE(mod.has_value());
    REQUIRE(fx::g_voids.size() == 1);
    CHECK(fx::g_voids[0].complete());
    box.pump();
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_unset == std::vector<int>{41});
}

TEST_CASE("an irreversible async binding is counted by revert", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.boom", "aio.boom()");
    REQUIRE(mod.has_value());
    CHECK(fx::g_voids[0].complete());
    box.pump();
    const auto report = box.revert(*mod);
    REQUIRE(report.has_value());
    CHECK(report->irreversible == 1);
}

TEST_CASE("a failed async call records no effect", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.failed_spawn", "ok = pcall(aio.spawn, 3)");
    REQUIRE(mod.has_value());
    CHECK(fx::g_ints[0].done.complete(Rhp::fail(errc::kLimitExceeded, "world full")));
    box.pump();
    const auto report = box.revert(*mod);
    REQUIRE(report.has_value());
    CHECK(report->undone == 0);
    CHECK(fx::g_despawned.empty());
}

TEST_CASE("a tuple async result spreads into several values", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("local n, s = aio.pair() return n, s"));
    const Rhp::request_id request = box.last_request();
    CHECK(fx::g_pairs[0].complete(std::tuple<int, std::string>{3, "three"}));
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK(**r == value_list{Rhp::value{3}, Rhp::value{"three"}});
}

TEST_CASE("only a script's own thread may call an async binding", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    SECTION("a coroutine the script created") {
        const auto r = box.exec("local co = coroutine.create(function() return aio.later(1) end) local ok, err = coroutine.resume(co) return ok, err");
        REQUIRE(r.has_value());
        CHECK((*r)[0] == Rhp::value{false});
        CHECK(message_of(*r, 1).find("asynchronous binding") != std::string::npos);
    }
    SECTION("a callback of a C function") {
        const auto r = box.exec("local ok, err = pcall(table.sort, {3, 1, 2}, function(a, b) aio.later(1) return a < b end) return ok, err");
        REQUIRE(r.has_value());
        CHECK((*r)[0] == Rhp::value{false});
        CHECK(message_of(*r, 1).find("asynchronous binding") != std::string::npos);
    }
    SECTION("a module's on_unload") {
        const auto mod = box.load("tests.async.on_unload", "function on_unload() aio.later(1) end");
        REQUIRE(mod.has_value());
        (void)box.unload(*mod);
    }
    CHECK(fx::g_ints.empty()); // refused before the binding ran
}

TEST_CASE("cancel ends a waiting request and a late success is taken back", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("aio.spawn(1) print('unreached')"));
    const Rhp::request_id request = box.last_request();
    box.cancel(request);
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->has_value());
    CHECK(r->error().code == errc::kCancelled);
    CHECK(fx::g_ints[0].done.stop_requested());
    CHECK(fx::g_ints[0].done.complete(9)); // the sandbox still holds the call
    CHECK(fx::g_despawned.empty());
    box.pump();
    CHECK(fx::g_despawned == std::vector<int>{9});
    CHECK(box.stats().async_compensated == 1);
    CHECK(out.lines.empty());
}

TEST_CASE("a result that arrived before the cancel is taken back at once", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("aio.spawn(1)"));
    const Rhp::request_id request = box.last_request();
    CHECK(fx::g_ints[0].done.complete(4));
    box.cancel(request);
    box.pump();
    CHECK(fx::g_despawned == std::vector<int>{4});
    CHECK(box.stats().async_compensated == 1);
}

TEST_CASE("unloading a module ends the async calls its handlers wait for", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.timer", "rhp.after(0, function() aio.spawn(2) print('spawned') end)");
    REQUIRE(mod.has_value());
    box.pump();
    REQUIRE(fx::g_ints.size() == 1);
    CHECK(box.stats().async_waiting == 1);
    REQUIRE(box.unload(*mod));
    CHECK(box.stats().async_waiting == 0);
    CHECK(fx::g_ints[0].done.stop_requested());
    CHECK(fx::g_ints[0].done.complete(12));
    box.pump();
    CHECK(fx::g_despawned == std::vector<int>{12});
    CHECK(out.lines.empty());
}

TEST_CASE("limits.async_ms times out the call and takes back a late result", "[script][async]") {
    capture out;
    auto clock = std::make_shared<manual_clock>();
    Rhp::limits limits;
    limits.async_ms = 50;
    sandbox box = make_box(out, limits, clock);
    REQUIRE(box.exec("local ok, err = pcall(aio.spawn, 1) return ok, tostring(err)"));
    const Rhp::request_id request = box.last_request();
    clock->now += std::chrono::milliseconds{20};
    box.pump();
    CHECK(box.pending(request));
    clock->now += std::chrono::milliseconds{40};
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((**r)[0] == Rhp::value{false});
    CHECK(message_of(**r, 1).find("timeout") != std::string::npos);
    CHECK(fx::g_ints[0].done.stop_requested());
    CHECK(fx::g_ints[0].done.complete(5));
    box.pump();
    CHECK(fx::g_despawned == std::vector<int>{5});

    REQUIRE(box.exec("return aio.later(1)")); // uncaught: the request fails with kTimeout
    const Rhp::request_id uncaught = box.last_request();
    clock->now += std::chrono::milliseconds{60};
    box.pump();
    const auto failed = result_of(out, uncaught);
    REQUIRE(failed.has_value());
    REQUIRE_FALSE(failed->has_value());
    CHECK(failed->error().code == errc::kTimeout);
}

TEST_CASE("waiting for an async result spends no instruction budget", "[script][async]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 5'000;
    sandbox box = make_box(out, limits);
    REQUIRE(box.exec("return aio.later(1)"));
    const Rhp::request_id request = box.last_request();
    for (int i = 0; i < 500; ++i) {
        box.pump();
    }
    CHECK(fx::g_ints[0].done.complete(1));
    box.pump();
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    CHECK(r->has_value());
}

TEST_CASE("timers frame callbacks event handlers and tasks may wait for async results", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.async.handlers", R"lua(
        rhp.after(0, function() print('timer ' .. aio.later(1)) end)
        rhp.every_frame(function() print('frame ' .. aio.later(2)) return false end, {times = 1})
        rhp.on('tests.async.ping', function() print('event ' .. aio.later(3)) end)
        local t = rhp.spawn(function() return aio.later(4) end)
        rhp.spawn(function() print('joined ' .. t:join()) end)
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.exec("rhp.publish('tests.async.ping')"));
    for (int i = 0; i < 3; ++i) {
        box.pump();
    }
    REQUIRE(fx::g_ints.size() == 4);
    for (auto& call : fx::g_ints) {
        CHECK(call.done.complete(call.arg * 10));
    }
    for (int i = 0; i < 3; ++i) {
        box.pump();
    }
    std::vector<std::string> lines = out.lines;
    std::ranges::sort(lines);
    CHECK(lines == std::vector<std::string>{"event 30", "frame 20", "joined 40", "timer 10"});
    CHECK(out.failures.empty());
}

TEST_CASE("a worker thread completes the call", "[script][async][threads]") {
    capture out;
    sandbox box = make_box(out);
    const auto direct = box.exec("return aio.echo('hi')");
    REQUIRE(direct);
    if (box.suspended() == 0) {
        // The worker finished before the call could wait (a slow machine, a sanitizer): the call
        // returned its result at once, and no on_result follows.
        CHECK(*direct == value_list{Rhp::value{"hi!"}});
        return;
    }
    const Rhp::request_id request = box.last_request();
    pump_until(box, out, request);
    const auto r = result_of(out, request);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK(**r == value_list{Rhp::value{"hi!"}});
}

TEST_CASE("many tasks wait at once for results completed by many threads", "[script][async][threads]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec(R"lua(
        total = 0
        for i = 1, 64 do rhp.spawn(function() local v = aio.later(i) total = total + v end) end
    )lua"));
    box.pump(); // the tasks start and wait
    REQUIRE(fx::g_ints.size() == 64);
    std::vector<std::thread> workers;
    for (int w = 0; w < 4; ++w) {
        workers.emplace_back([w] {
            for (std::size_t i = static_cast<std::size_t>(w); i < fx::g_ints.size(); i += 4) {
                (void)fx::g_ints[i].done.complete(fx::g_ints[i].arg);
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    for (int i = 0; i < 3; ++i) {
        box.pump();
    }
    const auto total = box.exec("return total");
    REQUIRE(total.has_value());
    CHECK(*total == value_list{Rhp::value{64 * 65 / 2}});
    CHECK(box.stats().async_waiting == 0);
}

TEST_CASE("cancel racing a completion on another thread ends cleanly", "[script][async][threads]") {
    for (int round = 0; round < 300; ++round) {
        capture out;
        sandbox box = make_box(out);
        const auto mod = box.load("tests.async.race", "function go() spawned = aio.spawn(1) end");
        REQUIRE(mod.has_value());
        REQUIRE(box.call(*mod, "go", {}));
        const Rhp::request_id request = box.last_request();
        std::thread worker{[d = fx::g_ints.at(0).done, round] { (void)d.complete(round); }};
        // Three orders: the cancel before the pump that would resume the request, the cancel after
        // it (the script got the entity), and the cancel racing a pump on a moving result.
        switch (round % 3) {
        case 0:
            box.cancel(request);
            box.pump();
            worker.join();
            break;
        case 1:
            worker.join();
            box.pump();
            box.cancel(request);
            break;
        default:
            box.pump();
            box.cancel(request);
            worker.join();
            break;
        }
        box.pump();
        box.pump();
        // Either the script received the entity (an effect of the module) or it was taken back.
        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(fx::g_despawned == std::vector<int>{round});
        CHECK(report->undone + box.stats().async_compensated == 1);
        if (round % 3 == 1) {
            CHECK(report->undone == 1); // it finished before the cancel
        }
    }
}

TEST_CASE("a pure async binding's success that nobody receives is counted as dropped", "[script][async]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("aio.later(1)"));
    box.cancel(box.last_request());
    box.pump();
    CHECK(fx::g_ints[0].done.complete(3));
    box.pump();
    CHECK(box.stats().async_dropped == 1);
    CHECK(box.stats().async_compensated == 0);
}

TEST_CASE("released leftovers still take back a late success after the sandbox is gone", "[script][async]") {
    std::optional<Rhp::promise<int>> done;
    Rhp::script::async_leftovers left;
    {
        capture out;
        sandbox box = make_box(out);
        REQUIRE(box.exec("aio.spawn(1)"));
        box.cancel(box.last_request());
        box.pump();
        done = fx::g_ints.at(0).done;
        left = box.release_async();
        CHECK(left.pending() == 1);
    }
    CHECK(left.pump() == 1); // nothing arrived yet
    CHECK(done->complete(44));
    CHECK(left.pump() == 0);
    CHECK(left.undone() == 1);
    CHECK(fx::g_despawned == std::vector<int>{44});
}

TEST_CASE("a sandbox destroyed while a call waits stops the producer", "[script][async]") {
    std::optional<Rhp::promise<int>> waiting;
    std::optional<Rhp::promise<int>> arrived;
    {
        capture out;
        sandbox box = make_box(out);
        REQUIRE(box.exec("aio.spawn(1)"));
        REQUIRE(box.exec("aio.spawn(2)"));
        waiting = fx::g_ints.at(0).done;
        arrived = fx::g_ints.at(1).done;
        CHECK(arrived->complete(22)); // arrived but never pumped
    }
    CHECK(waiting->stop_requested());
    CHECK_FALSE(waiting->complete(11)); // nobody receives it
    CHECK(fx::g_despawned == std::vector<int>{22});
}

TEST_CASE("stubs mark async bindings and give their result type", "[script][async][stubs]") {
    const std::string stubs = Rhp::script::stubs::generate<fx::aio_lib>(Rhp::role::kPatch);
    CHECK(stubs.find("---@async\n---@param arg1 integer\n---@return integer\nfunction aio.later(arg1) end") != std::string::npos);
    CHECK(stubs.find("---@async\n---@return integer\n---@return string\nfunction aio.pair() end") != std::string::npos);
}
