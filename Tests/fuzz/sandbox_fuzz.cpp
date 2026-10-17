// Sandbox escapes: arbitrary source runs as an observe-role identity (instruction, memory and wall
// limits on). Whatever it does, the host's variable stays untouched, what the sandbox hides stays
// hidden from a fresh module, and the process survives (ASan/UBSan report the rest).
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_support.hpp"

#include <rhp/core/limits.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>

namespace {

int g_secret = 1234;

int twice(int x) {
    return x * 2;
}

using game_lib = Rhp::lib<"game">::var<"secret", &g_secret>::fn<"twice", &twice>;

} // namespace

std::vector<std::string> rhp_fuzz_seeds() {
    return {
        R"(return game.twice(21))",
        R"(game.secret = 0)",
        R"(rawset(game, 'secret', 0))",
        R"(setmetatable(game, nil) game.secret = 0)",
        R"(local mt = getmetatable(game) if mt then mt.__newindex = nil end game.secret = 1)",
        R"(return io, os.execute, debug, package, dofile, loadfile, require)",
        R"(return string.dump(print))",
        R"(return load('\27Lua'))",
        R"(return load(string.char(27, 76, 117, 97, 84)))",
        R"(local f = load('return 1', 'x', 'b') return f)",
        R"(while true do end)",
        R"(local t = {} while true do t[#t + 1] = string.rep('x', 1024) end)",
        R"(local function f() return f() end return f())",
        R"(return coroutine.wrap(function() coroutine.yield(game.secret) end)())",
        R"(collectgarbage('stop') return collectgarbage('count'))",
        R"(return _ENV, _G, rhp)",
        R"(for k in pairs(_G) do _G[k] = nil end)",
        R"(return ('x'):rep(1e9))",
        R"(return string.format('%99d', 1))",
        R"(error(setmetatable({}, {__tostring = function() game.secret = 2 return 'x' end})))",
        R"(return utf8.char(0x10FFFF, 0x7FFFFFFF))",
        R"(return table.concat({}, ',', 1, 1e8))",
        R"(return math.tointeger(2^63), math.maxinteger // -1, 1 // 0)",
        R"(rhp.wait(1) game.secret = 3)",
        R"(return string.rep('a', 100, 'b'):gsub('a', '%0%0'))",
        R"(local t = {} for i = 1, 200 do t[i] = i end rhp.spawn(function() end, table.unpack(t)))",
        R"(local t = {} for i = 1, 200 do t[i] = i end rhp.on('a.b', function() end) rhp.publish('a.b', table.unpack(t)))",
        R"(rhp.spawn(function() while true do end end))",
        R"(rhp.every_frame(function() error('x') end))",
        R"(_G.k = setmetatable({}, {__gc = function() pcall(rhp.every, 1, print) pcall(rhp.spawn, print) end}))",
        R"(rhp.reschedule(rhp.every_frames(1, print), math.huge))",
    };
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view source{reinterpret_cast<const char*>(data), size};
    g_secret = 1234;
    {
        Rhp::script::sandbox_options opts;
        opts.caller_role = Rhp::role::kObserve;
        opts.limits.instructions = 200'000;
        opts.limits.memory = 16u << 20;
        opts.limits.wall_ms = 500;
        opts.output = [](std::string_view) {};
        Rhp::script::sandbox box{opts};
        RHP_FUZZ_CHECK(box.install<game_lib>().has_value());
        (void)box.exec(source, "fuzz");
        RHP_FUZZ_CHECK(g_secret == 1234);
        // A fresh module of the same identity still can't see what the sandbox hides.
        auto probe = box.load("probe", "return {ok = io == nil and debug == nil and package == nil and dofile == nil and loadfile == nil and string.dump == nil}");
        if (probe) {
            auto ok = box.exec("return require('probe').ok", "probe_check");
            RHP_FUZZ_CHECK(!ok || ok->empty() || ok->front() == Rhp::value{true});
        }
    }
    RHP_FUZZ_CHECK(g_secret == 1234);
    return 0;
}
