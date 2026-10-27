// rhp.buffer: byte buffers a script owns. Created with rhp.buffer.new(size) / rhp.buffer.from(bytes);
// read and written through methods: numbers of every width at a byte position (b:read_u32(pos,
// "be")), strings, string.pack formats (b:pack / b:unpack); sliced (b:slice) and viewed as typed
// spans (b:view("u8")[i]) without copying. Positions are 1-based, like string.byte and string.unpack.
// A buffer's __index is its methods table, so a method call costs a table lookup, not a C call.
//
// A buffer is script state like a table: its memory is a Lua userdata (counted in limits.memory),
// writes to it are never journaled, and it goes when nothing refers to it (slices and views keep it).

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <initializer_list>
#include <string>
#include <string_view>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/views_impl.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>

namespace Rhp::script::detail {

namespace {

constexpr std::string_view kBufferLabel = "rhp.buffer";

view_node& self_buffer(lua_State* L, std::string_view method) {
    auto* n = static_cast<view_node*>(luaL_testudata(L, 1, kBufferKey));
    if (n == nullptr) {
        raise(L, errc::kTypeMismatch, std::format("expected a buffer, got {}", stack{L}.type_name(1)), std::format("buffer:{}", method));
    }
    return *n;
}

view_node* new_buffer(lua_State* L, std::size_t size) {
    view_node* n = new_node(L, size, kBufferKey);
    n->shape = node_shape::kBytes;
    n->origin = node_origin::kInline;
    n->elem = elem_kind::kU8;
    n->writable = true;
    n->count = size;
    n->data = node_payload(n);
    n->label = kBufferLabel;
    return n;
}

std::size_t size_arg(lua_State* L, int index) {
    const lua_Integer size = luaL_checkinteger(L, index);
    if (size < 0) {
        raise(L, errc::kOutOfRange, std::format("a buffer's size can't be negative ({})", size), "rhp.buffer.new");
    }
    return static_cast<std::size_t>(size);
}

// rhp.buffer.new(size [, fill]): `size` bytes, each `fill` (default 0).
int buffer_new(lua_State* L) {
    const std::size_t size = size_arg(L, 1);
    const lua_Integer fill = luaL_optinteger(L, 2, 0);
    if (fill < 0 || fill > 255) {
        raise(L, errc::kOutOfRange, std::format("{} does not fit a byte", fill), "rhp.buffer.new");
    }
    view_node* n = new_buffer(L, size);
    std::memset(n->data, static_cast<int>(fill), size);
    return 1;
}

// rhp.buffer.from(bytes): a copy of a string, a buffer or a span (its bytes).
int buffer_from(lua_State* L) {
    if (lua_type(L, 1) == LUA_TSTRING) {
        std::size_t len = 0;
        const char* s = lua_tolstring(L, 1, &len);
        view_node* n = new_buffer(L, len);
        std::memcpy(n->data, s, len);
        return 1;
    }
    if (const view_node* src = to_span_node(L, 1)) {
        const place p = locate_or_raise(L, *src);
        view_node* n = new_buffer(L, p.size);
        std::memcpy(n->data, p.data, p.size);
        return 1;
    }
    raise(L, errc::kTypeMismatch, std::format("expected a string, a buffer or a span, got {}", stack{L}.type_name(1)), "rhp.buffer.from");
}

// The byte range [pos, pos + len) as an offset, raising when it isn't inside `size` bytes (labelled
// "buffer:<method>").
std::size_t position(lua_State* L, lua_Integer pos, std::size_t len, std::size_t size, std::string_view method) {
    if (pos < 1 || static_cast<lua_Unsigned>(pos) - 1 > size || len > size - (static_cast<std::size_t>(pos) - 1)) {
        raise(L, errc::kOutOfRange, std::format("bytes [{}, {}] out of range [1, {}]", pos, pos + static_cast<lua_Integer>(len) - 1, size),
                     std::format("buffer:{}", method));
    }
    return static_cast<std::size_t>(pos) - 1;
}

// The byte order argument at `index`: nil or "le" (little endian), "be" (big endian).
bool big_endian(lua_State* L, int index, std::string_view where) {
    if (lua_isnoneornil(L, index)) {
        return false;
    }
    std::size_t len = 0;
    const char* s = lua_tolstring(L, index, &len);
    const std::string_view order = s != nullptr && lua_type(L, index) == LUA_TSTRING ? std::string_view{s, len} : std::string_view{};
    if (order == "le") {
        return false;
    }
    if (order == "be") {
        return true;
    }
    raise(L, errc::kInvalidArgument, std::format("byte order must be \"le\" or \"be\", got {}", stack{L}.type_name(index)), where);
}

void order_bytes(std::byte* p, std::size_t n, bool big) noexcept {
    if (big != (std::endian::native == std::endian::big)) {
        std::reverse(p, p + n);
    }
}

// A read_* / write_* method's name (upvalue 2: a Lua string, no copy).
std::string_view method_name(lua_State* L) {
    std::size_t len = 0;
    const char* name = lua_tolstring(L, lua_upvalueindex(2), &len);
    return {name, len};
}

std::string method_label(lua_State* L) {
    return std::format("buffer:{}", method_name(L));
}

// b:read_<kind>(pos [, order]). Upvalues: 1 the elem_kind, 2 the method's name.
int buffer_read(lua_State* L) {
    view_node& n = self_buffer(L, "read");
    const auto k = static_cast<elem_kind>(lua_tointeger(L, lua_upvalueindex(1)));
    const lua_Integer pos = luaL_checkinteger(L, 2);
    const std::size_t es = elem_size(k);
    const bool big = big_endian(L, 3, kBufferLabel);
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, es, p.size, method_name(L));
    std::byte bytes[8];
    std::memcpy(bytes, p.data + at, es);
    order_bytes(bytes, es, big);
    push_elem(L, k, bytes);
    return 1;
}

// b:write_<kind>(pos, value [, order]) -> the position after it. Upvalues as buffer_read.
int buffer_write(lua_State* L) {
    view_node& n = self_buffer(L, "write");
    const auto k = static_cast<elem_kind>(lua_tointeger(L, lua_upvalueindex(1)));
    const lua_Integer pos = luaL_checkinteger(L, 2);
    const std::size_t es = elem_size(k);
    const bool big = big_endian(L, 4, kBufferLabel);
    std::byte bytes[8];
    if (const elem_error e = to_elem(L, 3, k, bytes); e != elem_error::kNone) {
        raise_elem(L, 3, k, e, method_label(L));
    }
    order_bytes(bytes, es, big);
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, "the buffer is read-only", method_label(L));
    }
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, es, p.size, method_name(L));
    if (before_write(L, n, p, at, es)) {
        std::memcpy(p.data + at, bytes, es);
    }
    lua_pushinteger(L, pos + static_cast<lua_Integer>(es));
    return 1;
}

// b:read_string(pos, len)
int buffer_read_string(lua_State* L) {
    view_node& n = self_buffer(L, "read_string");
    const lua_Integer pos = luaL_checkinteger(L, 2);
    const lua_Integer len = luaL_checkinteger(L, 3);
    if (len < 0) {
        raise(L, errc::kOutOfRange, std::format("a length can't be negative ({})", len), "buffer:read_string");
    }
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, static_cast<std::size_t>(len), p.size, "read_string");
    lua_pushlstring(L, reinterpret_cast<const char*>(p.data + at), static_cast<std::size_t>(len));
    return 1;
}

// b:write_string(pos, s) -> the position after it.
int buffer_write_string(lua_State* L) {
    view_node& n = self_buffer(L, "write_string");
    const lua_Integer pos = luaL_checkinteger(L, 2);
    std::size_t len = 0;
    const char* s = luaL_checklstring(L, 3, &len);
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, "the buffer is read-only", "buffer:write_string");
    }
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, len, p.size, "write_string");
    if (len > 0 && before_write(L, n, p, at, len)) {
        std::memcpy(p.data + at, s, len);
    }
    lua_pushinteger(L, pos + static_cast<lua_Integer>(len));
    return 1;
}

// b:tostring([i [, j]]): bytes i..j as a string.
int buffer_tostring_method(lua_State* L) {
    view_node& n = self_buffer(L, "tostring");
    const place p = locate_or_raise(L, n);
    const auto [first, last] = range_args(L, 2, p.size, "buffer:tostring");
    lua_pushlstring(L, reinterpret_cast<const char*>(p.data + first), last - first);
    return 1;
}

bool parse_kind(std::string_view name, elem_kind& out) noexcept {
    for (const elem_kind k : {elem_kind::kI8, elem_kind::kU8, elem_kind::kI16, elem_kind::kU16, elem_kind::kI32, elem_kind::kU32, elem_kind::kI64,
                              elem_kind::kU64, elem_kind::kF32, elem_kind::kF64, elem_kind::kByte}) {
        if (elem_name(k) == name) {
            out = k;
            return true;
        }
    }
    return false;
}

// b:view(kind [, pos [, count]]): a typed span over the bytes from pos (default 1): `count`
// elements (default: as many as fit). Shares the memory; elements need no alignment.
int buffer_view(lua_State* L) {
    view_node& n = self_buffer(L, "view");
    std::size_t len = 0;
    const char* name = luaL_checklstring(L, 2, &len);
    elem_kind k{};
    if (!parse_kind(std::string_view{name, len}, k)) {
        raise(L, errc::kInvalidArgument, std::format("unknown element type '{}' (i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, byte)", std::string_view{name, len}),
                     "buffer:view");
    }
    const lua_Integer pos = luaL_optinteger(L, 3, 1);
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(k);
    const std::size_t from = position(L, pos, 0, p.size, "view");
    const std::size_t fit = (p.size - from) / es;
    const lua_Integer count = luaL_optinteger(L, 4, static_cast<lua_Integer>(fit));
    if (count < 0 || static_cast<lua_Unsigned>(count) > fit) {
        raise(L, errc::kOutOfRange, std::format("{} elements of {} bytes from byte {} don't fit a buffer of {}", count, es, pos, p.size), "buffer:view");
    }
    push_part(L, 1, from, static_cast<std::size_t>(count), node_shape::kSpan, k);
    return 1;
}

// b:pack(pos, fmt, ...) -> the position after it: string.pack(fmt, ...) written at pos.
// Upvalue 1: string.pack.
int buffer_pack(lua_State* L) {
    view_node& n = self_buffer(L, "pack");
    const lua_Integer pos = luaL_checkinteger(L, 2);
    luaL_checkstring(L, 3);
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, "the buffer is read-only", "buffer:pack");
    }
    const int top = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    for (int i = 3; i <= top; ++i) {
        lua_pushvalue(L, i);
    }
    lua_call(L, top - 2, 1);
    std::size_t len = 0;
    const char* packed = lua_tolstring(L, -1, &len);
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, len, p.size, "pack");
    if (len > 0 && before_write(L, n, p, at, len)) {
        std::memcpy(p.data + at, packed, len);
    }
    lua_pushinteger(L, pos + static_cast<lua_Integer>(len));
    return 1;
}

// b:unpack(pos, fmt) -> the values, then the position after them: string.unpack(fmt, bytes) from pos.
// Upvalues: 1 string.unpack, 2 string.packsize.
int buffer_unpack(lua_State* L) {
    view_node& n = self_buffer(L, "unpack");
    const lua_Integer pos = luaL_checkinteger(L, 2);
    luaL_checkstring(L, 3);
    const place p = locate_or_raise(L, n);
    const std::size_t at = position(L, pos, 0, p.size, "unpack");
    std::size_t take = p.size - at;
    // A format of fixed size copies only what it reads (string.packsize refuses variable sizes).
    lua_pushvalue(L, lua_upvalueindex(2));
    lua_pushvalue(L, 3);
    if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
        const lua_Integer need = lua_tointeger(L, -1);
        if (need >= 0 && static_cast<lua_Unsigned>(need) < take) {
            take = static_cast<std::size_t>(need);
        }
    }
    lua_pop(L, 1);
    const int base = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, 3);
    lua_pushlstring(L, reinterpret_cast<const char*>(p.data + at), take);
    lua_call(L, 2, LUA_MULTRET);
    const int results = lua_gettop(L) - base;
    // The last result is the position after the values in the copied bytes: make it the buffer's.
    const lua_Integer next = lua_tointeger(L, -1);
    lua_pop(L, 1);
    lua_pushinteger(L, next + pos - 1);
    return results;
}

int buffer_tostring(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const result<place> p = locate(*n);
    const std::string text = p ? std::format("buffer: {} bytes", p->size) : std::string{"buffer: gone"};
    lua_pushlstring(L, text.data(), text.size());
    return 1;
}

void define_buffer_type(lua_State* L) {
    if (luaL_newmetatable(L, kBufferKey) == 0) {
        lua_pop(L, 1);
        return;
    }
    const int mt = lua_gettop(L);
    lua_pushliteral(L, "buffer");
    lua_setfield(L, mt, "__name");
    lua_pushcfunction(L, &buffer_tostring);
    lua_setfield(L, mt, "__tostring");
    lua_createtable(L, 0, 32);
    const int methods = lua_gettop(L);
    set_sequence_metamethods(L, mt, methods, true);
    const luaL_Reg plain[] = {
        {"read_string", &buffer_read_string},
        {"write_string", &buffer_write_string},
        {"tostring", &buffer_tostring_method},
        {"view", &buffer_view},
        {nullptr, nullptr},
    };
    for (const luaL_Reg* r = plain; r->name != nullptr; ++r) {
        lua_pushcfunction(L, r->func);
        lua_setfield(L, methods, r->name);
    }
    for (const elem_kind k : {elem_kind::kI8, elem_kind::kU8, elem_kind::kI16, elem_kind::kU16, elem_kind::kI32, elem_kind::kU32, elem_kind::kI64,
                              elem_kind::kU64, elem_kind::kF32, elem_kind::kF64}) {
        for (const bool write : {false, true}) {
            const std::string name = std::format("{}_{}", write ? "write" : "read", elem_name(k));
            lua_pushinteger(L, static_cast<lua_Integer>(k));
            lua_pushlstring(L, name.data(), name.size());
            lua_pushcclosure(L, write ? &buffer_write : &buffer_read, 2);
            lua_setfield(L, methods, name.c_str());
        }
    }
    // string.pack / unpack / packsize as the string library had them (a script can't swap them).
    lua_getglobal(L, "string");
    const int strings = lua_gettop(L);
    const bool have = lua_istable(L, strings);
    if (have) {
        lua_getfield(L, strings, "pack");
    } else {
        lua_pushnil(L);
    }
    lua_pushcclosure(L, &buffer_pack, 1);
    lua_setfield(L, methods, "pack");
    if (have) {
        lua_getfield(L, strings, "unpack");
        lua_getfield(L, strings, "packsize");
    } else {
        lua_pushnil(L);
        lua_pushnil(L);
    }
    lua_pushcclosure(L, &buffer_unpack, 2);
    lua_setfield(L, methods, "unpack");
    lua_settop(L, mt - 1);
}

} // namespace

void open_buffer_library(lua_State* L) {
    const int rhp = lua_absindex(L, -1);
    define_span_type(L);
    define_buffer_type(L);
    lua_createtable(L, 0, 2);
    lua_pushcfunction(L, &buffer_new);
    lua_setfield(L, -2, "new");
    lua_pushcfunction(L, &buffer_from);
    lua_setfield(L, -2, "from");
    lua_setfield(L, rhp, "buffer");
}

} // namespace Rhp::script::detail
