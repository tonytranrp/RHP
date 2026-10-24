#pragma once

// Shared pieces of rhp_bench: a raw Lua state (the twin of a sandbox) and sandbox options that
// keep output off the console.

#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/script/sandbox.hpp>

// Lua is compiled as C++ (cmake/lua/lua_cxx.cpp): its functions have C++ linkage.
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

namespace rhp_bench {

// A plain lua_State with the standard libraries: what a sandbox would be without RHP.
class raw_lua {
public:
    raw_lua() : L_(luaL_newstate()) { luaL_openlibs(L_); }
    ~raw_lua() { lua_close(L_); }
    raw_lua(const raw_lua&) = delete;
    raw_lua& operator=(const raw_lua&) = delete;

    [[nodiscard]] lua_State* get() const noexcept { return L_; }

    // Runs a chunk; the chunk's first result (if any) is left in the global `name`.
    void define(std::string_view name, std::string_view chunk) {
        REQUIRE(luaL_loadbuffer(L_, chunk.data(), chunk.size(), "bench") == LUA_OK);
        REQUIRE(lua_pcall(L_, 0, 1, 0) == LUA_OK);
        lua_setglobal(L_, std::string{name}.c_str());
    }

    // Calls global function `name` with no arguments; returns its first result as an integer.
    lua_Integer call(const char* name) {
        lua_getglobal(L_, name);
        if (lua_pcall(L_, 0, 1, 0) != LUA_OK) {
            FAIL(lua_tostring(L_, -1));
        }
        const lua_Integer r = lua_tointeger(L_, -1);
        lua_pop(L_, 1);
        return r;
    }

private:
    lua_State* L_;
};

inline Rhp::script::sandbox_options quiet() {
    Rhp::script::sandbox_options o;
    o.output = [](std::string_view) {};
    return o;
}

// Loads `source` as module `name` into `box` and fails the test if it doesn't load.
inline Rhp::module_id load(Rhp::script::sandbox& box, std::string_view name, std::string_view source) {
    auto mod = box.load(name, source);
    if (!mod) {
        FAIL(mod.error().message);
    }
    return *mod;
}

} // namespace rhp_bench
