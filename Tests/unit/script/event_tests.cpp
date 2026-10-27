#include <atomic>
#include <chrono>
#include <cstdint>
#include <latch>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp_test/script_support.hpp>

using Rhp::errc;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace event_tests_fixtures {

// A handle type with a wire conversion: a handle where a lib declares it, an integer elsewhere.
struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

// A handle type no lib declares and nothing converts: arrives as nil.
struct token_id {
    int v = 0;
    bool operator==(const token_id&) const = default;
};

} // namespace event_tests_fixtures

template <>
struct Rhp::convert<event_tests_fixtures::entity_id> {
    static Rhp::value to_value(const event_tests_fixtures::entity_id& e) { return Rhp::value{e.v}; }
    static Rhp::result<event_tests_fixtures::entity_id> from_value(const Rhp::value& v) {
        if (const auto* i = v.get_if<std::int64_t>()) {
            return event_tests_fixtures::entity_id{static_cast<int>(*i)};
        }
        return Rhp::fail(Rhp::errc::kTypeMismatch, "expected an entity id");
    }
};

namespace event_tests_fixtures {

inline int g_counter = 0;

inline bool is_alive(const entity_id& e) {
    return e.v != 0;
}

inline int id_of(entity_id e) {
    return e.v;
}

inline constexpr Rhp::lua_event<"tests.events.ping", int, std::string_view> ping{};
inline constexpr Rhp::lua_event<"tests.events.spawned", entity_id> spawned{};
inline constexpr Rhp::lua_event<"tests.events.token", token_id> token{};
inline constexpr Rhp::lua_event<"tests.events.many", bool, double, std::string, Rhp::value> many{};
// Two event types with one name: subscribing to that name is refused.
inline constexpr Rhp::lua_event<"tests.events.dup", int> dup_int{};
inline constexpr Rhp::lua_event<"tests.events.dup", double> dup_double{};
inline constexpr Rhp::lua_event<"tests.events.bare"> bare{};

inline void fire_ping(int n) {
    ping.fire(n, "inner");
}

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>;
using world_lib = Rhp::lib<"world">::fn<"id_of", &id_of>::handle<"entity", entity_id, &is_alive>;
using trigger_lib = Rhp::lib<"trigger">::fn<"ping", &fire_ping>;

} // namespace event_tests_fixtures

namespace {

namespace fx = event_tests_fixtures;

struct capture {
    std::vector<std::string> lines;
    std::vector<std::pair<Rhp::request_id, Rhp::result<value_list>>> results;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture& out, Rhp::limits limits = {}, Rhp::script::handler_error_policy policy = Rhp::script::handler_error_policy::kReport) {
    sandbox_options options;
    options.limits = limits;
    options.handler_errors = policy;
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_result = [&out](Rhp::request_id id, const Rhp::result<value_list>& r) { out.results.emplace_back(id, r); };
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    REQUIRE(box.install<fx::trigger_lib>());
    return box;
}

using rhp_test::code_of;

value_list values(const Rhp::result<value_list>& r) {
    return r ? *r : value_list{Rhp::value{"error: " + r.error().message}};
}

constexpr std::string_view kPrinter = R"lua(
    rhp.on("tests.events.ping", function(n, text) print(tostring(n) .. " " .. text) end)
)lua";

} // namespace

TEST_CASE("an event fired on the sandbox's thread is delivered at once", "[script][events]") {
    fx::g_counter = 0;
    capture out;
    {
        sandbox box = make_box(out);
        REQUIRE(box.load("tests.events.sync", R"lua(
            rhp.on("tests.events.ping", function(n, text) counter.value = counter.value + n print(text) end)
        )lua"));
        CHECK(fx::ping.listeners() == 1);
        fx::ping.fire(3, "hi");
        CHECK(fx::g_counter == 3);
        CHECK(out.lines == std::vector<std::string>{"hi"});
        CHECK(box.suspended() == 0);
        CHECK(out.results.empty()); // handlers that finish at once aren't reported
    }
    CHECK(fx::ping.listeners() == 0);
    CHECK(fx::g_counter == 0);
}

TEST_CASE("an event fired on another thread waits for the next pump", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.events.queued", kPrinter));
    {
        std::jthread worker{[] {
            std::string text = "from thread";
            fx::ping.fire(1, text);
            text.assign("clobbered!!"); // the queued copy must not see this
            fx::ping.fire(2, "second");
            fx::ping.fire(3, "third");
        }};
    }
    CHECK(out.lines.empty());
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"1 from thread", "2 second", "3 third"});
    box.pump();
    CHECK(out.lines.size() == 3);
}

TEST_CASE("the thread that last pumped owns synchronous delivery", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.events.owner", kPrinter));
    {
        std::jthread worker{[&box] { box.pump(); }};
    }
    fx::ping.fire(1, "queued"); // this thread no longer owns the sandbox
    CHECK(out.lines.empty());
    box.pump(); // now it does again
    CHECK(out.lines == std::vector<std::string>{"1 queued"});
    fx::ping.fire(2, "direct");
    CHECK(out.lines == std::vector<std::string>{"1 queued", "2 direct"});
}

TEST_CASE("one fire reaches owned sandboxes at once and queues for the others", "[script][events]") {
    capture near_out;
    capture far_out;
    sandbox near = make_box(near_out);
    sandbox far = make_box(far_out);
    REQUIRE(near.load("tests.events.near", kPrinter));
    REQUIRE(far.load("tests.events.far", kPrinter));
    {
        std::jthread worker{[&far] { far.pump(); }}; // `far` now belongs to another thread
    }
    CHECK(fx::ping.listeners() == 2);
    fx::ping.fire(1, "mixed");
    CHECK(near_out.lines == std::vector<std::string>{"1 mixed"});
    CHECK(far_out.lines.empty());
    far.pump();
    CHECK(far_out.lines == std::vector<std::string>{"1 mixed"});
}

TEST_CASE("events without arguments", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.events.bare", "rhp.on('tests.events.bare', function(...) print(select('#', ...)) end)"));
    STATIC_REQUIRE(decltype(fx::bare)::arity == 0);
    fx::bare.fire();
    CHECK(out.lines == std::vector<std::string>{"0"});
}

TEST_CASE("rhp.off can't remove another module's subscription", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    const auto owner = box.load("tests.events.owner_sub", "id = rhp.on('tests.events.ping', function() print('kept') end) function get() return id end");
    const auto thief = box.load("tests.events.thief", "function steal(id) rhp.off(id) end");
    REQUIRE(owner.has_value());
    REQUIRE(thief.has_value());
    const auto id = box.call(*owner, "get");
    REQUIRE(id.has_value());
    REQUIRE_FALSE(id->empty());
    const auto stolen = box.call(*thief, "steal", std::span<const Rhp::value>{&id->front(), 1});
    REQUIRE_FALSE(stolen.has_value());
    CHECK(stolen.error().code == errc::kNotFound);
    fx::ping.fire(0, "");
    CHECK(out.lines == std::vector<std::string>{"kept"});
}

TEST_CASE("handlers run in subscription order each as its own request", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    const auto a = box.load("tests.events.order_a", R"lua(
        rhp.on("tests.events.ping", function() print("a1") end)
        function more() rhp.on("tests.events.ping", function() print("a2") end) end
    )lua");
    const auto b = box.load("tests.events.order_b", "rhp.on('tests.events.ping', function() print('b1') end)");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(box.call(*a, "more"));
    CHECK(fx::ping.listeners() == 1); // one sandbox, however many handlers
    fx::ping.fire(0, "");
    CHECK(out.lines == std::vector<std::string>{"a1", "b1", "a2"});
}

TEST_CASE("a failing handler faults only its own module at once outside a run", "[script][events]") {
    fx::g_counter = 0;
    capture out;
    sandbox box = make_box(out, {}, Rhp::script::handler_error_policy::kFault);
    const auto bad = box.load("tests.events.bad", R"lua(
        counter.value = 1
        rhp.on("tests.events.ping", function() error("handler failed") end)
    )lua");
    const auto good = box.load("tests.events.good", "rhp.on('tests.events.ping', function(n) print('good ' .. n) end)");
    REQUIRE(bad.has_value());
    REQUIRE(good.has_value());
    fx::ping.fire(4, "x");
    const auto info = box.status(*bad);
    REQUIRE(info.has_value());
    CHECK(info->state == module_state::kFaulted);
    REQUIRE(info->fault.has_value());
    CHECK(info->fault->message.find("handler failed") != std::string::npos);
    CHECK(fx::g_counter == 0);
    CHECK(box.status(*good)->state == module_state::kActive);
    CHECK(out.lines == std::vector<std::string>{"good 4"});

    fx::ping.fire(5, "y");
    CHECK(out.lines == std::vector<std::string>{"good 4", "good 5"});
    CHECK(fx::ping.listeners() == 1);
}

TEST_CASE("handlers may wait", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.events.waiter", R"lua(
        rhp.on("tests.events.ping", function(n) print("before " .. n) rhp.next_frame() print("after " .. n) return n end)
    )lua"));
    fx::ping.fire(1, "");
    fx::ping.fire(2, "");
    CHECK(out.lines == std::vector<std::string>{"before 1", "before 2"});
    CHECK(box.suspended() == 2);
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"before 1", "before 2", "after 1", "after 2"});
    REQUIRE(out.results.size() == 2);
    CHECK(out.results[0].second.has_value());
    CHECK(out.results[1].second.has_value());
}

TEST_CASE("an event fired inside a run is delivered within it", "[script][events]") {
    fx::g_counter = 0;
    capture out;
    sandbox box = make_box(out, {}, Rhp::script::handler_error_policy::kFault);
    const auto counting = box.load("tests.events.counting", "rhp.on('tests.events.ping', function(n) counter.value = counter.value + n end)");
    REQUIRE(counting.has_value());
    CHECK(box.exec<int>("trigger.ping(5) return counter.value") == 5);

    SECTION("a failing handler faults its module when the run ends") {
        const auto bad = box.load("tests.events.inner_bad", "rhp.on('tests.events.ping', function() error('inner failure') end)");
        REQUIRE(bad.has_value());
        const auto r = box.exec("trigger.ping(1) return 'kept going'");
        CHECK(values(r) == value_list{Rhp::value{"kept going"}});
        CHECK(box.status(*bad)->state == module_state::kFaulted);
        CHECK(box.status(*counting)->state == module_state::kActive);
        CHECK(fx::g_counter == 6);
    }

    SECTION("a handler inside a run may wait") {
        REQUIRE(box.load("tests.events.inner_wait", "rhp.on('tests.events.ping', function(n) rhp.next_frame() print('later ' .. n) end)"));
        CHECK(values(box.exec("trigger.ping(2) return 'done'")) == value_list{Rhp::value{"done"}});
        CHECK(out.lines.empty());
        CHECK(box.suspended() == 1);
        box.pump();
        CHECK(out.lines == std::vector<std::string>{"later 2"});
    }
}

TEST_CASE("handle arguments arrive as handles where a lib declares them", "[script][events]") {
    capture out_world;
    capture out_plain;
    sandbox with_world = make_box(out_world);
    REQUIRE(with_world.install<fx::world_lib>());
    sandbox plain = make_box(out_plain);

    constexpr std::string_view kWorldHandler = R"lua(
        rhp.on("tests.events.spawned", function(e) print(type(e) .. " " .. world.id_of(e)) end)
        rhp.on("tests.events.token", function(t) print("token " .. tostring(t)) end)
    )lua";
    constexpr std::string_view kPlainHandler = R"lua(
        rhp.on("tests.events.spawned", function(e) print(math.type(e) .. " " .. e) end)
        rhp.on("tests.events.token", function(t) print("token " .. tostring(t)) end)
    )lua";
    REQUIRE(with_world.load("tests.events.world", kWorldHandler));
    REQUIRE(plain.load("tests.events.plain", kPlainHandler));
    CHECK(fx::spawned.listeners() == 2);

    fx::spawned.fire(fx::entity_id{7});
    fx::token.fire(fx::token_id{9});
    CHECK(out_world.lines == std::vector<std::string>{"userdata 7", "token nil"});
    CHECK(out_plain.lines == std::vector<std::string>{"integer 7", "token nil"});
}

TEST_CASE("event arguments of every convertible kind cross over", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.events.kinds", R"lua(
        rhp.on("tests.events.many", function(b, d, s, v)
            print(tostring(b), tostring(d), s, type(v), #v, v[2])
        end)
    )lua"));
    fx::many.fire(true, 2.5, std::string{"text"}, Rhp::value{Rhp::value::array{Rhp::value{1}, Rhp::value{"two"}}});
    CHECK(out.lines == std::vector<std::string>{"true\t2.5\ttext\ttable\t2\ttwo"});
}

TEST_CASE("rhp.on validates the event and the handler", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    fx::dup_int.fire(1);
    fx::dup_double.fire(1.0);
    CHECK(code_of(box.exec("rhp.on('Not An Event', function() end)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.on('tests.events.nope', function() end)")) == errc::kOk); // a script event
    CHECK(code_of(box.exec("rhp.on('tests.events.dup', function() end)")) == errc::kAlreadyLoaded);
    CHECK(code_of(box.exec("rhp.on('tests.events.ping', 5)")) == errc::kTypeMismatch);
    CHECK(code_of(box.exec("rhp.on(5, function() end)")) == errc::kTypeMismatch);
    CHECK(fx::ping.listeners() == 0);
    STATIC_REQUIRE(decltype(fx::many)::arity == 4);
    STATIC_REQUIRE(decltype(fx::ping)::name == "tests.events.ping");
}

TEST_CASE("unsubscribing: rhp.off revert unload and destruction", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.events.off", R"lua(
        first = rhp.on("tests.events.ping", function() print("first") end)
        second = rhp.on("tests.events.ping", function() print("second") end)
        function drop(which) rhp.off(which == 1 and first or second) end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->effects == 2);
    REQUIRE(box.call(*mod, "drop", 1));
    fx::ping.fire(0, "");
    CHECK(out.lines == std::vector<std::string>{"second"});
    CHECK(fx::ping.listeners() == 1);
    REQUIRE(box.call(*mod, "drop", 2));
    CHECK(fx::ping.listeners() == 0); // the sandbox's last handler detaches it
    CHECK(box.status(*mod)->effects == 0);
    CHECK(code_of(box.call(*mod, "drop", 2)) == errc::kNotFound);

    const auto reverted = box.load("tests.events.reverted", kPrinter);
    REQUIRE(reverted.has_value());
    CHECK(fx::ping.listeners() == 1);
    REQUIRE(box.revert(*reverted));
    CHECK(fx::ping.listeners() == 0);

    const auto unloaded = box.load("tests.events.unloaded", kPrinter);
    REQUIRE(unloaded.has_value());
    CHECK(fx::ping.listeners() == 1);
    REQUIRE(box.unload(*unloaded));
    CHECK(fx::ping.listeners() == 0);

    {
        capture other_out;
        sandbox other = make_box(other_out);
        REQUIRE(other.load("tests.events.other", kPrinter));
        REQUIRE(box.load("tests.events.again", kPrinter));
        CHECK(fx::ping.listeners() == 2);
    }
    CHECK(fx::ping.listeners() == 1);
    out.lines.clear();
    fx::ping.fire(8, "left");
    CHECK(out.lines == std::vector<std::string>{"8 left"});
}

TEST_CASE("a handler can unsubscribe a later handler of the same delivery", "[script][events]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.events.self_off", R"lua(
        local second
        rhp.on("tests.events.ping", function() print("first") rhp.off(second) end)
        second = rhp.on("tests.events.ping", function() print("second") end)
    )lua");
    REQUIRE(mod.has_value());
    fx::ping.fire(0, "");
    CHECK(out.lines == std::vector<std::string>{"first"});
    CHECK(box.status(*mod)->effects == 1);

    // Next time the id is unknown: rhp.off fails, which is reported (the handler and its module stay).
    fx::ping.fire(0, "");
    CHECK(out.lines == std::vector<std::string>{"first", "first"});
    CHECK(box.status(*mod)->state == module_state::kActive);
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kNotFound);
    CHECK(out.failures[0].kind == Rhp::script::handler_kind::kEvent);
    CHECK(out.failures[0].source == "tests.events.ping");
    CHECK(fx::ping.listeners() == 1);
}

TEST_CASE("handlers from game code have their own budget", "[script][events]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 50'000;
    sandbox box = make_box(out, limits);
    const auto spin = box.load("tests.events.spin", "rhp.on('tests.events.ping', function() while true do end end)");
    const auto busy = box.load("tests.events.busy", R"lua(
        rhp.on("tests.events.ping", function() local s = 0 for i = 1, 5000 do s = s + i end print(s) end)
    )lua");
    REQUIRE(spin.has_value());
    REQUIRE(busy.has_value());
    fx::ping.fire(0, "");
    CHECK(box.status(*spin)->state == module_state::kActive); // reported, not faulted
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kBudgetExceeded);
    for (int i = 0; i < 10; ++i) { // each delivery has a budget of its own
        fx::ping.fire(0, "");
    }
    CHECK(out.lines.size() == 11);
    CHECK(out.failures.size() == 11);
    CHECK(box.status(*busy)->state == module_state::kActive);
}

TEST_CASE("events queued for a sandbox that is destroyed are dropped", "[script][events]") {
    {
        capture out;
        sandbox box = make_box(out);
        REQUIRE(box.load("tests.events.dropped", kPrinter));
        std::jthread worker{[] { fx::ping.fire(1, "never delivered"); }};
        worker.join();
    }
    CHECK(fx::ping.listeners() == 0);
    fx::ping.fire(1, "nobody listens"); // a no-op
}

namespace event_detach_fixtures {

// A listener whose delivery blocks until released, to catch detach() returning while it still runs.
class slow_listener final : public Rhp::script::detail::event_listener {
public:
    [[nodiscard]] std::thread::id listener_thread() const noexcept override { return owner.load(); }
    void deliver(std::string_view, const Rhp::script::detail::event_args&) override {
        delivering = true;
        entered.count_down();
        while (!release.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        delivering = false;
    }
    void enqueue(std::string_view, const Rhp::script::detail::event_args&) noexcept override {}

    std::atomic<std::thread::id> owner{};
    std::atomic<bool> delivering{false};
    std::atomic<bool> release{false};
    std::latch entered{1};
};

} // namespace event_detach_fixtures

TEST_CASE("detaching a listener waits for its delivery on another thread", "[script][events][threads]") {
    Rhp::script::detail::event_state state;
    event_detach_fixtures::slow_listener l;
    std::jthread firer{[&] {
        l.owner = std::this_thread::get_id(); // delivered synchronously on this thread
        state.attach(&l);
        state.fire("fx.detach", Rhp::script::detail::event_args{});
    }};
    l.entered.wait();
    std::jthread releaser{[&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        l.release = true;
    }};
    state.detach(&l);
    const bool still_delivering = l.delivering.load();
    CHECK_FALSE(still_delivering);
    CHECK(state.listeners() == 0);
}
