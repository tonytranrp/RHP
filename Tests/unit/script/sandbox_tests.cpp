#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <rhp_test/hardening.hpp>
#include <rhp_test/script_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/puc_lua/lua_internals.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/testing.hpp>

using Rhp::errc;
using Rhp::role;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace sandbox_tests_fixtures {

inline int g_counter = 0;

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>;

// A handle type std::format can't show, and a struct view of a host object: tostring shows hashes.
struct opaque {
    int id = 0;
    bool operator==(const opaque&) const = default;
};

inline bool opaque_alive(const opaque&) {
    return true;
}

inline opaque make_opaque() {
    return opaque{7};
}

struct spot {
    float x = 0;
};

inline spot g_spot{};

inline spot& the_spot() {
    return g_spot;
}

using shown_lib = Rhp::lib<"shown">::handle<"opaque", opaque, &opaque_alive>::fn<"make", &make_opaque> //
    ::view<"spot", spot>::field<"x", &spot::x>::fn<"where", &the_spot>;

} // namespace sandbox_tests_fixtures

namespace {

namespace fx = sandbox_tests_fixtures;

struct output_capture {
    std::vector<std::string> lines;
};

sandbox make_box(output_capture& out, role caller = role::kPatch) {
    sandbox_options options;
    options.caller_role = caller;
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    return sandbox{std::move(options)};
}

// A sandbox with counter_lib installed and the counter reset.
sandbox make_counter_box(output_capture& out, role caller = role::kPatch) {
    fx::g_counter = 0;
    sandbox box = make_box(out, caller);
    REQUIRE(box.install<fx::counter_lib>());
    return box;
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

// The script returned nil into an optional.
template <class T>
bool is_nil_result(const Rhp::result<std::optional<T>>& r) {
    return r.has_value() && !r->has_value();
}

// The hex number at the end of what tostring, %p or a described result shows ("table: 0x1f2e",
// "table: 00001F2E", "0x1f2e").
std::uint64_t shown_number(std::string_view text) {
    text = text.substr(text.rfind(' ') + 1);
    if (text.starts_with("0x")) {
        text.remove_prefix(2);
    }
    std::uint64_t n = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), n, 16);
    CHECK(parsed.ptr == text.data() + text.size());
    return n;
}

std::string describe(const Rhp::error& err) {
    return err.message + " | " + err.where + " | " + err.traceback;
}

using rhp_test::counting_resource;

// Returns "" when the environment matches the restricted standard library, else what's wrong.
constexpr std::string_view kRestrictedStdlibProbe = R"lua(
local problems = {}
local present = {
    "assert", "error", "getmetatable", "ipairs", "next", "pairs", "pcall", "print", "rawequal",
    "rawget", "rawlen", "rawset", "select", "setmetatable", "tonumber", "tostring", "type",
    "xpcall", "_VERSION", "load", "string", "table", "math", "utf8", "coroutine", "os", "require",
}
local absent = { "dofile", "loadfile", "collectgarbage", "package", "io", "debug" }
for _, name in ipairs(present) do
    if _G[name] == nil then problems[#problems + 1] = "missing " .. name end
end
for _, name in ipairs(absent) do
    if _G[name] ~= nil then problems[#problems + 1] = "present " .. name end
end
if string.dump ~= nil then problems[#problems + 1] = "present string.dump" end
if type(string.format) ~= "function" then problems[#problems + 1] = "missing string.format" end
if type(table.concat) ~= "function" then problems[#problems + 1] = "missing table.concat" end
if type(math.floor) ~= "function" then problems[#problems + 1] = "missing math.floor" end
if type(utf8.char) ~= "function" then problems[#problems + 1] = "missing utf8.char" end
if type(coroutine.wrap) ~= "function" then problems[#problems + 1] = "missing coroutine.wrap" end
if type(os.time) ~= "function" then problems[#problems + 1] = "missing os.time" end
if type(os.clock) ~= "function" then problems[#problems + 1] = "missing os.clock" end
for key in pairs(os) do
    if key ~= "time" and key ~= "clock" then problems[#problems + 1] = "present os." .. key end
end
return table.concat(problems, ", ")
)lua";

constexpr std::string_view kFullStdlibProbe = R"lua(
local problems = {}
local present = { "dofile", "loadfile", "collectgarbage", "require", "package", "io", "debug" }
for _, name in ipairs(present) do
    if _G[name] == nil then problems[#problems + 1] = "missing " .. name end
end
if type(string.dump) ~= "function" then problems[#problems + 1] = "missing string.dump" end
if type(os.execute) ~= "function" then problems[#problems + 1] = "missing os.execute" end
if type(os.getenv) ~= "function" then problems[#problems + 1] = "missing os.getenv" end
if type(io.open) ~= "function" then problems[#problems + 1] = "missing io.open" end
return table.concat(problems, ", ")
)lua";

} // namespace

TEST_CASE("observe and patch get the restricted standard library", "[script][sandbox]") {
    const role caller = GENERATE(role::kObserve, role::kPatch);
    CAPTURE(caller);
    output_capture out;
    sandbox box = make_box(out, caller);
    REQUIRE(box.caller_role() == caller);

    const auto scratch = box.exec<std::string>(kRestrictedStdlibProbe);
    REQUIRE(scratch.has_value());
    CHECK(*scratch == "");

    // Same view from inside a module.
    const auto mod = box.load("tests.stdlib", std::string{"function probe() "} + std::string{kRestrictedStdlibProbe} + " end");
    REQUIRE(mod.has_value());
    const auto values = box.call(*mod, "probe");
    REQUIRE(values.has_value());
    REQUIRE(values->size() == 1);
    REQUIRE((*values)[0] == Rhp::value{""});
}

TEST_CASE("admin gets the full standard library", "[script][sandbox]") {
    rhp_test::needs(Rhp::hardening::kDev, "admin's full standard library");
    output_capture out;
    sandbox box = make_box(out, role::kAdmin);
    const auto problems = box.exec<std::string>(kFullStdlibProbe);
    REQUIRE(problems.has_value());
    CHECK(*problems == "");
}

TEST_CASE("hardened admin gets patch's standard library", "[script][sandbox][hardening]") {
    // admin_stdlib off (a host above hardening dev); a lan or production build has no other kind.
    const bool asked = GENERATE(false, Rhp::kBuildHardening != Rhp::hardening::kDev);
    CAPTURE(asked);
    sandbox box{sandbox_options{.caller_role = role::kAdmin, .admin_stdlib = asked, .output = [](std::string_view) {}}};
    const auto problems = box.exec<std::string>(kRestrictedStdlibProbe);
    REQUIRE(problems.has_value());
    CHECK(*problems == "");
    CHECK(box.exec("setmetatable({}, {__gc = print})").error().code == errc::kForbidden);
    CHECK(box.caller_role() == role::kAdmin); // admin's own rights stay (rhp.patch, admin-tagged bindings)
}

TEST_CASE("above dev Lua is built without io package debug and os's process and file functions", "[script][sandbox][hardening]") {
    // A plain state with every library luaL_openlibs opens: what isn't compiled in stays nil.
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    constexpr std::string_view probe = R"lua(
        local seen = {}
        for _, name in ipairs({"io", "package", "debug", "require"}) do
            if _G[name] ~= nil then seen[#seen + 1] = name end
        end
        for _, name in ipairs({"execute", "exit", "getenv", "remove", "rename", "setlocale", "tmpname"}) do
            if os[name] ~= nil then seen[#seen + 1] = "os." .. name end
        end
        assert(type(os.time()) == "number" and type(os.clock()) == "number" and type(os.date("%Y")) == "string")
        return table.concat(seen, " ")
    )lua";
    REQUIRE(luaL_loadbufferx(L, probe.data(), probe.size(), "=probe", "t") == LUA_OK);
    REQUIRE(lua_pcall(L, 0, 1, 0) == LUA_OK);
    const std::string seen = lua_tostring(L, -1);
    lua_close(L);
    if constexpr (Rhp::kBuildHardening == Rhp::hardening::kDev) {
        CHECK(seen == "io package debug require os.execute os.exit os.getenv os.remove os.rename os.setlocale os.tmpname");
    } else {
        CHECK(seen == "");
    }
}

TEST_CASE("load accepts text only for every role", "[script][sandbox]") {
    SECTION("binary chunks are refused even for admin and mode b") {
        rhp_test::needs(Rhp::hardening::kDev, "admin's full standard library");
        output_capture out;
        sandbox box = make_box(out, role::kAdmin);
        const auto refused = box.exec(R"lua(
            local bytecode = string.dump(function() return 1 end)
            local f1, msg1 = load(bytecode)
            local f2, msg2 = load(bytecode, "chunk", "b")
            local f3, msg3 = load(bytecode, "chunk", "bt")
            return f1 == nil and f2 == nil and f3 == nil, type(msg1), type(msg2), type(msg3)
        )lua");
        REQUIRE(refused.has_value());
        REQUIRE(refused->size() == 4);
        CHECK((*refused)[0] == Rhp::value{true});
        CHECK((*refused)[1] == Rhp::value{"string"});
        CHECK((*refused)[2] == Rhp::value{"string"});
        CHECK((*refused)[3] == Rhp::value{"string"});
    }

    SECTION("text chunks run in the calling module's environment") {
        const role caller = GENERATE(role::kObserve, role::kPatch, role::kAdmin);
        CAPTURE(caller);
        output_capture out;
        sandbox box = make_box(out, caller);
        REQUIRE(box.exec<int>("return load('return 1')()") == 1);

        REQUIRE(box.exec("y = 7"));
        REQUIRE(box.exec<int>("return load('return y')()") == 7);

        const auto mod = box.load("tests.loader", R"lua(
            z = 3
            load("w = z + 1")()
            function get() return load("return w")() end
        )lua");
        REQUIRE(mod.has_value());
        const auto values = box.call(*mod, "get");
        REQUIRE(values.has_value());
        REQUIRE(values->size() == 1);
        CHECK((*values)[0] == Rhp::value{4});
        // The scratch module never saw the module's globals.
        CHECK(is_nil_result(box.exec<std::optional<int>>("return w")));
    }
}

TEST_CASE("only admin may give a table a finalizer", "[script][sandbox][gc]") {
    // Lua runs __gc with its hooks off: no limit, cancel or deadline would stop one that loops.
    SECTION("observe and patch: a metatable with __gc is refused") {
        const role caller = GENERATE(role::kObserve, role::kPatch);
        CAPTURE(caller);
        output_capture out;
        sandbox box = make_box(out, caller);
        const auto refused = box.exec("setmetatable({}, {__gc = function() while true do end end})");
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().code == errc::kForbidden);
        CHECK(contains(refused.error().message, "needs role admin"));
        CHECK(refused.error().where == "setmetatable");
        // Any value counts (Lua marks the object for finalization when __gc isn't nil).
        CHECK(box.exec("setmetatable({}, {__gc = false})").error().code == errc::kForbidden);

        // A __gc added after setmetatable never runs: Lua checks for one only when the metatable is set.
        REQUIRE(box.exec("local mt = {} keep = setmetatable({}, mt) mt.__gc = function() print('finalized') end keep = nil"));
        REQUIRE(box.collect_garbage());
        CHECK(out.lines.empty());

        // Everything else setmetatable does still works, <close> included.
        CHECK(box.exec<int>("return setmetatable({}, {__index = function() return 5 end}).x") == 5);
        CHECK(box.exec("setmetatable({}, setmetatable({}, {__index = {__gc = print}}))")); // only the metatable's own field counts
        CHECK(box.exec("local t = setmetatable({}, {__metatable = 'locked'}) setmetatable(t, {})").error().code == errc::kRuntime);
        REQUIRE(box.exec("do local x <close> = setmetatable({}, {__close = function() print('closed') end}) end"));
        CHECK(out.lines == std::vector<std::string>{"closed"});
    }

    SECTION("a __close that loops is still stopped") {
        Rhp::limits limits;
        limits.instructions = 100'000;
        sandbox_options options;
        options.limits = limits;
        options.output = [](std::string_view) {};
        sandbox box{std::move(options)};
        const auto stopped = box.exec("do local x <close> = setmetatable({}, {__close = function() while true do end end}) end");
        REQUIRE_FALSE(stopped.has_value());
        CHECK(stopped.error().code == errc::kBudgetExceeded);
    }

    SECTION("admin keeps the standard setmetatable") {
        rhp_test::needs(Rhp::hardening::kDev, "admin's full standard library");
        output_capture out;
        sandbox box = make_box(out, role::kAdmin);
        REQUIRE(box.exec("setmetatable({}, {__gc = function() print('finalized') end})"));
        REQUIRE(box.collect_garbage());
        CHECK(out.lines == std::vector<std::string>{"finalized"});
    }
}

TEST_CASE("tostring and %p show a keyed hash instead of an address", "[script][sandbox][addresses]") {
    output_capture out;
    sandbox box = make_box(out, role::kObserve);
    // One object always shows the same value, tostring and %p agree, and live objects never share one.
    REQUIRE(box.exec(R"lua(
        local t = {}
        local text = tostring(t)
        local live, seen = {}, {}
        for i = 1, 2000 do
            live[i] = {}
            local s = tostring(live[i])
            assert(not seen[s], "two live tables show the same value")
            seen[s] = true
        end
        assert(tostring(t) == text, "a table's value changed")
        print(text .. "\t" .. string.format("%p", t))
    )lua"));
    REQUIRE(out.lines.size() == 1);
    const std::string_view line = out.lines[0];
    CHECK(shown_number(line.substr(0, line.find('\t'))) == shown_number(line.substr(line.find('\t') + 1)));
    CHECK(box.exec<std::string>("return string.format('%p', 1)") == "(null)"); // nothing to show, as before

    // A C function's address is the program's: a plain Lua state shows it, each sandbox a hash of its own.
    lua_State* raw = luaL_newstate();
    luaL_openlibs(raw);
    lua_getglobal(raw, "string");
    lua_getfield(raw, -1, "len");
    const auto address = reinterpret_cast<std::uintptr_t>(lua_topointer(raw, -1));
    CHECK(shown_number(luaL_tolstring(raw, -1, nullptr)) == address);
    lua_close(raw);
    const auto shown = box.exec<std::string>("return tostring(string.len)");
    REQUIRE(shown.has_value());
    CHECK(shown_number(*shown) != address);
    sandbox other = make_box(out);
    CHECK(other.exec<std::string>("return tostring(string.len)") != shown);

    // A result RHP can't convert is described with the value tostring shows.
    const auto described = box.exec("return string.len");
    REQUIRE(described.has_value());
    REQUIRE(described->front().is_string());
    CHECK(shown_number(*described->front().get_if<std::string>()) == shown_number(*shown));
}

TEST_CASE("handles and struct views show a keyed hash instead of an address", "[script][sandbox][addresses]") {
    output_capture out;
    sandbox box = make_box(out, role::kObserve);
    REQUIRE(box.install<fx::shown_lib>());
    // A handle shows what %p shows for its userdata (a hash), not the userdata's address.
    REQUIRE(box.exec("local h = shown.make() print(tostring(h)) print(string.format('%p', h))"));
    REQUIRE(out.lines.size() == 2);
    CHECK(out.lines[0].starts_with("opaque: "));
    CHECK(shown_number(out.lines[0]) == shown_number(out.lines[1]));
    // A struct view hashes its object's address: two views of it agree, and the address never shows.
    const auto address = reinterpret_cast<std::uintptr_t>(&fx::g_spot);
    const auto shown_spot = box.exec<std::string>("return tostring(shown.where())");
    REQUIRE(shown_spot.has_value());
    const std::string& first = *shown_spot;
    CHECK(first.starts_with("spot: "));
    CHECK(box.exec<std::string>("return tostring(shown.where())") == first);
    CHECK(shown_number(first) != address);
    CHECK_FALSE(contains(first, std::format("{}", static_cast<const void*>(&fx::g_spot))));
    sandbox other = make_box(out, role::kObserve);
    REQUIRE(other.install<fx::shown_lib>());
    CHECK(other.exec<std::string>("return tostring(shown.where())") != first); // each sandbox has its own key
}

TEST_CASE("the value shown for an address is SipHash-2-4 under the sandbox's key", "[script][sandbox][addresses]") {
    // The reference vector: key 00..0f, message 00..07 (a light userdata of that value) -> 0x93f5f5799a932462.
    namespace internals = Rhp::script::detail::internals;
    std::array<std::byte, 16> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(i);
    }
    lua_State* L = luaL_newstate();
    internals::set_address_key(L, key);
    lua_pushlightuserdata(L, reinterpret_cast<void*>(std::uintptr_t{0x0706050403020100}));
    CHECK(reinterpret_cast<std::uintptr_t>(internals::shown_pointer(L, -1)) == 0x93f5f5799a932462);
    CHECK(shown_number(luaL_tolstring(L, -1, nullptr)) == 0x93f5f5799a932462);
    lua_close(L);
}

TEST_CASE("each module has its own environment", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_box(out);

    const auto a = box.load("tests.env.a", R"lua(
        shared = "a"
        function get() return shared end
        function own_g() return _G == _ENV and _G.shared == "a" end
    )lua");
    const auto b = box.load("tests.env.b", "function get() return shared end");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(*a != *b);

    const auto from_a = box.call(*a, "get");
    REQUIRE(from_a.has_value());
    REQUIRE(from_a->size() == 1);
    CHECK((*from_a)[0] == Rhp::value{"a"});

    const auto from_b = box.call(*b, "get");
    REQUIRE(from_b.has_value());
    CHECK((from_b->empty() || (*from_b)[0].is_nil()));

    const auto own_g = box.call(*a, "own_g");
    REQUIRE(own_g.has_value());
    REQUIRE(own_g->size() == 1);
    CHECK((*own_g)[0] == Rhp::value{true});

    // Scratch globals persist across exec calls but stay out of modules.
    REQUIRE(box.exec("x = 5"));
    REQUIRE(box.exec<int>("return x") == 5);
    CHECK(is_nil_result(box.exec<std::optional<std::string>>("return shared")));
    const auto x_in_b = box.load("tests.env.c", "function get() return x end");
    REQUIRE(x_in_b.has_value());
    const auto x_value = box.call(*x_in_b, "get");
    REQUIRE(x_value.has_value());
    CHECK((x_value->empty() || (*x_value)[0].is_nil()));
}

TEST_CASE("print goes to the output callback", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("print('a', 1)"));
    REQUIRE(box.exec("print('single')"));
    REQUIRE(box.exec("print(nil, true, 2.5)"));
    REQUIRE(box.exec("print()"));
    REQUIRE(out.lines.size() == 4);
    CHECK(out.lines[0] == "a\t1");
    CHECK(out.lines[1] == "single");
    CHECK(out.lines[2] == "nil\ttrue\t2.5");
    CHECK(out.lines[3] == "");
}

TEST_CASE("exec returns values and reports errors", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);

    SECTION("every returned value") {
        const auto values = box.exec("return 1, 'a'");
        REQUIRE(values.has_value());
        REQUIRE(values->size() == 2);
        CHECK((*values)[0] == Rhp::value{1});
        CHECK((*values)[1] == Rhp::value{"a"});

        const auto none = box.exec("local unused = 1");
        REQUIRE(none.has_value());
        CHECK(none->empty());

        const auto table = box.exec("return { 1, 2, 3 }");
        REQUIRE(table.has_value());
        REQUIRE(table->size() == 1);
        CHECK(box.exec<std::vector<int>>("return { 1, 2, 3 }") == std::vector<int>{1, 2, 3});
        CHECK(box.exec<double>("return 0.5") == 0.5);
        CHECK(box.exec<std::string>("return 'x' .. 1") == "x1");
    }

    SECTION("compile error") {
        const auto bad = box.exec("return +");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kCompile);
    }

    SECTION("runtime error has a traceback") {
        const auto bad = box.exec("local function inner() error('boom') end\ninner()");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kRuntime);
        CHECK(contains(bad.error().message, "boom"));
        CHECK_FALSE(bad.error().traceback.empty());
    }

    SECTION("a failing run reverts only its own effects") {
        REQUIRE(box.exec("counter.value = 1"));
        REQUIRE(fx::g_counter == 1);

        const auto bad = box.exec("counter.value = 2\ncounter.value = 3\nerror('nope')");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kRuntime);
        CHECK(fx::g_counter == 1);

        const auto scratch = box.status(box.scratch_module());
        REQUIRE(scratch.has_value());
        CHECK(scratch->scratch);
        CHECK(scratch->effects == 1);
        CHECK(scratch->state == module_state::kActive);

        // The sandbox keeps working.
        REQUIRE(box.exec("counter.value = counter.value + 10"));
        CHECK(fx::g_counter == 11);
    }
}

TEST_CASE("install exposes a lib once", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);
    CHECK(box.exec<std::string>("return type(counter)") == "userdata");

    const auto again = box.install<fx::counter_lib>();
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().code == errc::kAlreadyLoaded);

    // A standard library global is taken too.
    const auto clash = box.install<Rhp::lib<"string">>();
    REQUIRE_FALSE(clash.has_value());
    CHECK(clash.error().code == errc::kAlreadyLoaded);
    CHECK(box.exec<std::string>("return string.rep('a', 2)") == "aa");
}

TEST_CASE("load validates names and runs the chunk", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);

    SECTION("invalid names") {
        for (const std::string_view name : {"Bad", "a..b", "", ".a", "a.", "a b", "a-b"}) {
            CAPTURE(name);
            const auto bad = box.load(name, "return {}");
            REQUIRE_FALSE(bad.has_value());
            CHECK(bad.error().code == errc::kInvalidArgument);
        }
        CHECK(box.list().size() == 1);
    }

    SECTION("loading a loaded name reloads it") {
        const auto first = box.load("tests.dup", "return {}");
        REQUIRE(first.has_value());
        const auto again = box.load("tests.dup", "return {}");
        REQUIRE(again.has_value());
        CHECK(*again == *first);
        CHECK(box.status(*first)->revision == Rhp::revision_id{2});
        CHECK(box.list().size() == 2);
    }

    SECTION("compile error registers nothing") {
        const auto bad = box.load("tests.broken", "function (");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kCompile);
        const auto found = box.find("tests.broken");
        REQUIRE_FALSE(found.has_value());
        CHECK(found.error().code == errc::kNotFound);
        // The name is still free.
        CHECK(box.load("tests.broken", "return {}").has_value());
    }

    SECTION("runtime error faults the module and reverts its effects") {
        const auto bad = box.load("low_grav", "counter.value = 5\nerror('boom')");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kRuntime);
        CHECK(contains(describe(bad.error()), "low_grav:2"));
        CHECK(fx::g_counter == 0);

        const auto found = box.find("low_grav");
        REQUIRE(found.has_value());
        const auto info = box.status(*found);
        REQUIRE(info.has_value());
        CHECK(info->name == "low_grav");
        CHECK(info->state == module_state::kFaulted);
        CHECK(info->effects == 0);
        CHECK_FALSE(info->scratch);
        REQUIRE(info->fault.has_value());
        CHECK(info->fault->code == errc::kRuntime);

        // A faulted module can't be called.
        const auto call = box.call(*found, "anything");
        REQUIRE_FALSE(call.has_value());
        CHECK(call.error().code == errc::kInvalidArgument);
    }

    SECTION("on_load from the returned table") {
        const auto mod = box.load("tests.onload.table", R"lua(
            local M = {}
            function M.on_load() print("loaded table") end
            return M
        )lua");
        REQUIRE(mod.has_value());
        REQUIRE(out.lines == std::vector<std::string>{"loaded table"});
    }

    SECTION("on_load as a global when nothing is returned") {
        const auto mod = box.load("tests.onload.global", "function on_load() print('loaded global') end");
        REQUIRE(mod.has_value());
        REQUIRE(out.lines == std::vector<std::string>{"loaded global"});
    }

    SECTION("successful load is listed and active") {
        const auto mod = box.load("tests.ok", "counter.value = 3");
        REQUIRE(mod.has_value());
        CHECK(fx::g_counter == 3);
        REQUIRE(box.find("tests.ok") == *mod);
        const auto info = box.status(*mod);
        REQUIRE(info.has_value());
        CHECK(info->id == *mod);
        CHECK(info->state == module_state::kActive);
        CHECK(info->effects == 1);
        CHECK_FALSE(info->fault.has_value());
        CHECK(box.list().size() == 2);
    }
}

TEST_CASE("call runs exported functions", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);
    const auto mod = box.load("tests.calls", R"lua(
        local M = {}
        function M.add(a, b) return a + b end
        function M.pair() return 1, "two" end
        function M.nothing() end
        function M.fail() counter.value = 9 error("call failed") end
        M.not_a_function = 3
        return M
    )lua");
    REQUIRE(mod.has_value());

    SECTION("arguments and results") {
        const auto sum = box.call(*mod, "add", 2, 3);
        REQUIRE(sum.has_value());
        REQUIRE(sum->size() == 1);
        CHECK((*sum)[0] == Rhp::value{5});

        const Rhp::value args[] = {Rhp::value{1.5}, Rhp::value{2}};
        const auto spanned = box.call(*mod, "add", std::span<const Rhp::value>{args});
        REQUIRE(spanned.has_value());
        CHECK((*spanned)[0] == Rhp::value{3.5});

        const auto pair = box.call(*mod, "pair");
        REQUIRE(pair.has_value());
        REQUIRE(pair->size() == 2);
        CHECK((*pair)[1] == Rhp::value{"two"});

        const auto nothing = box.call(*mod, "nothing");
        REQUIRE(nothing.has_value());
        CHECK(nothing->empty());
    }

    SECTION("unknown function and module") {
        const auto missing = box.call(*mod, "missing");
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error().code == errc::kNotFound);

        const auto ghost = box.call(Rhp::module_id{987654}, "add", 1, 2);
        REQUIRE_FALSE(ghost.has_value());
        CHECK(ghost.error().code == errc::kNotFound);
    }

    SECTION("inactive module") {
        REQUIRE(box.revert(*mod));
        const auto reverted = box.call(*mod, "add", 1, 2);
        REQUIRE_FALSE(reverted.has_value());
        CHECK(reverted.error().code == errc::kInvalidArgument);
    }

    SECTION("runtime error faults the module") {
        const auto failed = box.call(*mod, "fail");
        REQUIRE_FALSE(failed.has_value());
        CHECK(failed.error().code == errc::kRuntime);
        CHECK(contains(describe(failed.error()), "call failed"));
        CHECK(fx::g_counter == 0);
        const auto info = box.status(*mod);
        REQUIRE(info.has_value());
        CHECK(info->state == module_state::kFaulted);
        CHECK(info->effects == 0);
        REQUIRE(info->fault.has_value());
    }
}

TEST_CASE("revert and unload", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);
    fx::g_counter = 42;
    const auto mod = box.load("tests.revert", R"lua(
        counter.value = 1
        counter.value = 2
        function on_unload() print("bye") end
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(fx::g_counter == 2);
    REQUIRE(box.status(*mod)->effects == 2);

    SECTION("revert") {
        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(report->undone == 2);
        CHECK(report->irreversible == 0);
        CHECK(report->clean());
        CHECK(fx::g_counter == 42);
        const auto info = box.status(*mod);
        REQUIRE(info.has_value());
        CHECK(info->state == module_state::kReverted);
        CHECK(info->effects == 0);
        CHECK(box.find("tests.revert") == *mod);

        // Reverting again undoes nothing.
        const auto again = box.revert(*mod);
        REQUIRE(again.has_value());
        CHECK(again->undone == 0);
    }

    SECTION("unload") {
        const auto report = box.unload(*mod);
        REQUIRE(report.has_value());
        CHECK(report->undone == 2);
        CHECK(fx::g_counter == 42);
        CHECK(out.lines == std::vector<std::string>{"bye"});
        const auto found = box.find("tests.revert");
        REQUIRE_FALSE(found.has_value());
        CHECK(found.error().code == errc::kNotFound);
        CHECK_FALSE(box.status(*mod).has_value());
        // The name can be loaded again.
        CHECK(box.load("tests.revert", "return {}").has_value());
    }

    SECTION("unknown ids") {
        const auto revert = box.revert(Rhp::module_id{987654});
        REQUIRE_FALSE(revert.has_value());
        CHECK(revert.error().code == errc::kNotFound);
        const auto unload = box.unload(Rhp::module_id{987654});
        REQUIRE_FALSE(unload.has_value());
        CHECK(unload.error().code == errc::kNotFound);
        CHECK_FALSE(box.status(Rhp::module_id{987654}).has_value());
    }
}

TEST_CASE("checkpoint and revert_to", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);

    SECTION("undoes everything after the mark in any module") {
        REQUIRE(box.exec("counter.value = 1"));
        REQUIRE(box.checkpoint("before"));
        REQUIRE(box.load("tests.cp", "counter.value = 2"));
        REQUIRE(box.exec("counter.value = 3"));
        REQUIRE(fx::g_counter == 3);

        const auto report = box.revert_to("before");
        REQUIRE(report.has_value());
        CHECK(report->undone == 2);
        CHECK(fx::g_counter == 1);
    }

    SECTION("unknown tag") {
        const auto missing = box.revert_to("never");
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error().code == errc::kNotFound);
    }

    SECTION("re-checkpointing moves the tag") {
        REQUIRE(box.checkpoint("cp"));
        REQUIRE(box.exec("counter.value = 5"));
        REQUIRE(box.checkpoint("cp"));
        REQUIRE(box.exec("counter.value = 6"));
        REQUIRE(box.revert_to("cp"));
        CHECK(fx::g_counter == 5);
    }

    SECTION("later checkpoints are dropped") {
        REQUIRE(box.checkpoint("first"));
        REQUIRE(box.exec("counter.value = 1"));
        REQUIRE(box.checkpoint("second"));
        REQUIRE(box.exec("counter.value = 2"));
        REQUIRE(box.revert_to("first"));
        CHECK(fx::g_counter == 0);
        const auto second = box.revert_to("second");
        REQUIRE_FALSE(second.has_value());
        CHECK(second.error().code == errc::kNotFound);
    }
}

TEST_CASE("revert_all unloads every module and reverts scratch", "[script][sandbox]") {
    output_capture out;
    sandbox box = make_counter_box(out);
    fx::g_counter = 7;
    REQUIRE(box.exec("counter.value = 1"));
    REQUIRE(box.load("tests.all.a", "counter.value = 2"));
    REQUIRE(box.load("tests.all.b", "counter.value = 3"));
    REQUIRE(box.list().size() == 3);

    const auto report = box.revert_all();
    CHECK(report.undone == 3);
    CHECK(report.clean());
    CHECK(fx::g_counter == 7);

    const auto modules = box.list();
    REQUIRE(modules.size() == 1);
    CHECK(modules[0].scratch);
    CHECK(modules[0].id == box.scratch_module());
    CHECK_FALSE(box.find("tests.all.a").has_value());

    // Still usable.
    REQUIRE(box.exec("counter.value = 8"));
    CHECK(fx::g_counter == 8);
}

TEST_CASE("revert_all puts back the library tables scripts changed", "[script][sandbox][builtins]") {
    output_capture out;
    sandbox box = make_box(out);
    // Nothing stands between a script and the library tables (no proxy: no cost on the hot path).
    CHECK(box.exec<bool>("return getmetatable(string) == nil and rawget(string, 'upper') == string.upper and getmetatable('').__index == string") == true);
    REQUIRE(box.load("tests.builtins", R"lua(
        string.upper = function() return "hijacked" end
        string.shout = string.upper
        string.rep = nil
        table.insert = nil
        math.pi = 3
        setmetatable(math, {__index = function() return 42 end})
        getmetatable("").__add = function() return "added" end
        getmetatable("").__index = {len = function() return -1 end}
        os.time = function() return 0 end
        rhp.after = nil
        rhp.buffer.new = nil
        coroutine.wrap = nil
    )lua"));
    REQUIRE(box.exec("utf8.char = print"));
    // The tables are shared: every module of the identity sees the changes until it reverts.
    CHECK(box.exec<std::string>("return string.upper('x')") == "hijacked");
    CHECK(box.exec<int>("return ('abc'):len()") == -1);
    CHECK(box.exec<int>("return math.nothing") == 42);

    (void)box.revert_all();
    CHECK(box.list().size() == 1); // scratch only
    const auto problems = box.exec<std::string>(R"lua(
        local problems = {}
        local function check(ok, what) if not ok then problems[#problems + 1] = what end end
        check(string.upper("x") == "X", "string.upper")
        check(string.shout == nil, "string.shout")
        check(string.rep("a", 2) == "aa", "string.rep")
        check(type(table.insert) == "function", "table.insert")
        check(math.pi > 3.14, "math.pi")
        check(getmetatable(math) == nil and math.nothing == nil, "math's metatable")
        check(("10" + 1) == 11, "string arithmetic")
        check(getmetatable("").__index == string and ("abc"):len() == 3, "string methods")
        check(os.time() > 0, "os.time")
        check(type(rhp.after) == "function", "rhp.after")
        check(type(rhp.buffer.new) == "function", "rhp.buffer.new")
        check(type(coroutine.wrap) == "function", "coroutine.wrap")
        check(utf8.char(65) == "A", "utf8.char")
        return table.concat(problems, ", ")
    )lua");
    CHECK(problems == "");

    // What RHP itself put in a library table after the sandbox was made stays: the test bridge's clock.
    rhp_test::manual_clock clock;
    sandbox_options options;
    options.clock = clock.fn();
    options.output = [](std::string_view) {};
    sandbox tested{std::move(options)};
    REQUIRE(tested.enable_testing(Rhp::script::testing_options{.fake_os_epoch = 1000}));
    REQUIRE(tested.exec("os.time = nil os.clock = nil"));
    (void)tested.revert_all();
    CHECK(tested.exec<std::int64_t>("return os.time()") == 1000);
}

TEST_CASE("destroying a sandbox reverts everything", "[script][sandbox]") {
    output_capture out;
    {
        sandbox box = make_counter_box(out);
        fx::g_counter = 100;
        REQUIRE(box.exec("counter.value = 1"));
        REQUIRE(box.load("tests.dtor", "counter.value = 2"));
        REQUIRE(fx::g_counter == 2);
    }
    CHECK(fx::g_counter == 100);
}

TEST_CASE("a moved sandbox keeps working", "[script][sandbox]") {
    output_capture out;
    sandbox first = make_counter_box(out);
    REQUIRE(first.exec("x = 1\ncounter.value = 1"));

    sandbox second{std::move(first)};
    CHECK(second.exec<int>("return x") == 1);
    REQUIRE(second.exec("print('moved')"));
    CHECK(out.lines == std::vector<std::string>{"moved"});

    sandbox third = make_box(out);
    third = std::move(second);
    CHECK(third.exec<int>("return x + counter.value") == 2);
    CHECK(fx::g_counter == 1);

    third.revert_all();
    CHECK(fx::g_counter == 0);
}

TEST_CASE("sandbox memory accounting", "[script][sandbox]") {
    SECTION("memory_used is non-zero") {
        output_capture out;
        sandbox box = make_box(out);
        const std::size_t before = box.memory_used();
        CHECK(before > 0);
        REQUIRE(box.exec("big = string.rep('x', 100000)"));
        CHECK(box.memory_used() > before);
    }

    SECTION("a custom memory resource sees the allocations") {
        counting_resource resource;
        {
            sandbox_options options;
            options.memory = &resource;
            sandbox box{std::move(options)};
            CHECK(resource.allocations() > 0);
            const std::size_t before = resource.allocations();
            REQUIRE(box.exec("t = {} for i = 1, 100 do t[i] = tostring(i) end"));
            CHECK(resource.allocations() > before);
            CHECK(resource.live_bytes() > 0);
        }
        CHECK(resource.live_bytes() == 0);
    }
}

TEST_CASE("sandbox: returning deeply nested tables never overruns the Lua stack", "[script][sandbox][fuzz]") {
    // Found by the sandbox_escape fuzzer: `return _G` walked nested tables past the C stack slots
    // Lua guarantees a C function.
    output_capture out;
    sandbox box = make_box(out);
    auto deep = box.exec("local t = {} local c = t for i = 1, 60 do c.x = {} c = c.x end return t");
    REQUIRE(deep);
    CHECK(deep->size() == 1);
    // Too deep to convert: the result is described instead ("table: 0x..."), as for functions.
    auto too_deep = box.exec("local t = {} local c = t for i = 1, 200 do c.x = {} c = c.x end return t");
    REQUIRE(too_deep);
    REQUIRE(too_deep->size() == 1);
    CHECK(too_deep->front().is_string());
    CHECK(box.exec("return _G"));
}

TEST_CASE("calls with many arguments fit the request coroutine", "[script][sandbox]") {
    Rhp::script::sandbox box;
    const auto mod = box.load("tests.sandbox.many_args", "function count(...) return select('#', ...) end");
    REQUIRE(mod.has_value());
    std::vector<Rhp::value> args;
    for (int i = 0; i < 64; ++i) {
        args.emplace_back(i);
    }
    const auto r = box.call(*mod, "count", args);
    REQUIRE(r.has_value());
    CHECK(r->at(0) == Rhp::value{64});
}
