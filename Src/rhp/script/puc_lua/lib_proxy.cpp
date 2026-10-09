#include <cstddef>
#include <format>
#include <string>
#include <string_view>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

namespace {

// Upvalues: 1 members, 2 getters. Args: proxy, key.
int lib_index(lua_State* L) {
    lua_pushvalue(L, 2);
    if (lua_rawget(L, lua_upvalueindex(1)) != LUA_TNIL) {
        return 1;
    }
    lua_pop(L, 1);
    lua_pushvalue(L, 2);
    if (lua_rawget(L, lua_upvalueindex(2)) == LUA_TFUNCTION) {
        lua_call(L, 0, 1);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// Upvalues: 1 setters, 2 label. Args: proxy, key, value.
int lib_newindex(lua_State* L) {
    lua_pushvalue(L, 2);
    if (lua_rawget(L, lua_upvalueindex(1)) == LUA_TFUNCTION) {
        lua_pushvalue(L, 3);
        lua_call(L, 1, 0);
        return 0;
    }
    lua_pop(L, 1);
    const stack s{L};
    std::size_t len = 0;
    const char* key = luaL_tolstring(L, 2, &len);
    s.raise(make_error(errc::kInvalidArgument, std::format("{}.{} is not writable", s.upvalue_string(2), std::string_view{key, len})));
}

// Upvalue: 1 label.
int lib_tostring(lua_State* L) {
    lua_pushfstring(L, "lib: %s", lua_tostring(L, lua_upvalueindex(1)));
    return 1;
}

} // namespace

void make_lib_proxy(stack& s, std::string_view label) {
    lua_State* L = s.state();
    const int setters = lua_gettop(L);
    const int getters = setters - 1;
    const int members = setters - 2;

    lua_newuserdatauv(L, 0, 0); // the proxy: userdata, so rawset/rawget/pairs can't bypass the metatable
    const int proxy = lua_gettop(L);
    lua_createtable(L, 0, 6);
    lua_pushvalue(L, members);
    lua_pushvalue(L, getters);
    lua_pushcclosure(L, &lib_index, 2);
    lua_setfield(L, -2, "__index");
    lua_pushvalue(L, setters);
    s.push_string(label);
    lua_pushcclosure(L, &lib_newindex, 2);
    lua_setfield(L, -2, "__newindex");
    s.push_string(label);
    lua_pushcclosure(L, &lib_tostring, 1);
    lua_setfield(L, -2, "__tostring");
    s.push_string(label);
    lua_setfield(L, -2, "__name");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_setmetatable(L, proxy);

    lua_replace(L, members); // proxy takes the members slot
    lua_settop(L, members);
}

} // namespace Rhp::script::detail
