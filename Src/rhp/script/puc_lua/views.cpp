// Typed views (spans), struct views and what spans and byte buffers share: their nodes, element
// reads and writes, the span metatable, struct view types, and the stack members binding
// trampolines use (push_host_view, attach_view_source, to_span, to_object, define_view_type).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/puc_lua/views_impl.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>

namespace Rhp::script::detail {

namespace {

// The node, padded so a payload after it is aligned for anything.
constexpr std::size_t kNodeSize = (sizeof(view_node) + alignof(std::max_align_t) - 1) / alignof(std::max_align_t) * alignof(std::max_align_t);

constexpr const char* kFieldsField = "__rhp_fields";     // a view type's fields: name -> light userdata (field_desc)
constexpr const char* kOrderField = "__rhp_order";       // their names in declaration order
constexpr const char* kTypeTagField = "__rhp_view_type"; // the C++ type (view_type_info::type_tag; not a handle's __rhp_type)

[[noreturn]] void raise(lua_State* L, error err) {
    stack{L}.raise(err);
}

[[noreturn]] void raise(lua_State* L, errc code, std::string message, std::string_view where) {
    stack{L}.raise(make_error(code, std::move(message), std::string{where}));
}

std::string_view type_name_of(lua_State* L, int index) {
    return stack{L}.type_name(index);
}

std::string kind_name(const view_node& n) {
    return n.shape == node_shape::kBytes ? std::string{"buffer"} : std::format("span<{}>", elem_name(n.elem));
}

[[noreturn]] void raise_index(lua_State* L, const view_node& n, lua_Integer i, std::size_t count) {
    if (count == 0) {
        raise(L, errc::kOutOfRange, std::format("index {} out of range (the {} is empty)", i, kind_name(n)), n.label);
    }
    raise(L, errc::kOutOfRange, std::format("index {} out of range [1, {}]", i, count), n.label);
}

// The integer index at `key` (an integer-valued number), else raises.
lua_Integer index_arg(lua_State* L, const view_node& n, int key) {
    int is_integer = 0;
    const lua_Integer i = lua_tointegerx(L, key, &is_integer);
    if (is_integer == 0 || lua_type(L, key) != LUA_TNUMBER) {
        raise(L, errc::kInvalidArgument, std::format("index must be an integer, got {}", lua_type(L, key) == LUA_TNUMBER ? std::format("{}", lua_tonumber(L, key)) : std::string{type_name_of(L, key)}),
              n.label);
    }
    return i;
}

view_node& self_node(lua_State* L, const char* what) {
    view_node* n = to_span_node(L, 1);
    if (n == nullptr) {
        raise(L, errc::kTypeMismatch, std::format("expected a span or a buffer, got {}", type_name_of(L, 1)), what);
    }
    return *n;
}

template <class T>
T load(const std::byte* p) noexcept {
    T v;
    std::memcpy(&v, p, sizeof v);
    return v;
}

template <class T>
void store(std::byte* p, T v) noexcept {
    std::memcpy(p, &v, sizeof v);
}

bool integer_fits(elem_kind k, lua_Integer v) noexcept {
    switch (k) {
    case elem_kind::kI8: return std::in_range<std::int8_t>(v);
    case elem_kind::kU8:
    case elem_kind::kByte: return std::in_range<std::uint8_t>(v);
    case elem_kind::kI16: return std::in_range<std::int16_t>(v);
    case elem_kind::kU16: return std::in_range<std::uint16_t>(v);
    case elem_kind::kI32: return std::in_range<std::int32_t>(v);
    case elem_kind::kU32: return std::in_range<std::uint32_t>(v);
    case elem_kind::kU64: return v >= 0;
    default: return true;
    }
}

// Reads element i (1-based at stack index `key`) of node n.
int read_at(lua_State* L, view_node& n, int key) {
    const lua_Integer i = index_arg(L, n, key);
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    const std::size_t count = p.size / es;
    if (i < 1 || static_cast<lua_Unsigned>(i) > count) {
        raise_index(L, n, i, count);
    }
    push_elem(L, n.elem, p.data + (static_cast<std::size_t>(i) - 1) * es);
    return 1;
}

// Writes the value at `value` to element i (at `key`) of node n.
int write_at(lua_State* L, view_node& n, int key, int value) {
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, std::format("the {} is read-only", kind_name(n)), n.label);
    }
    const lua_Integer i = index_arg(L, n, key);
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    const std::size_t count = p.size / es;
    if (i < 1 || static_cast<lua_Unsigned>(i) > count) {
        raise_index(L, n, i, count);
    }
    std::byte converted[8];
    if (const elem_error e = to_elem(L, value, n.elem, converted); e != elem_error::kNone) {
        raise_elem(L, value, n.elem, e, std::string{n.label});
    }
    const std::size_t at = (static_cast<std::size_t>(i) - 1) * es;
    if (before_write(L, n, p, at, es)) {
        std::memcpy(p.data + at, converted, es);
    }
    return 0;
}

// ---- metamethods of spans and buffers ------------------------------------------------------------

// Upvalue 1: the methods table. Integer keys are elements; names are methods.
int node_index(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    if (lua_type(L, 2) == LUA_TNUMBER) {
        return read_at(L, *n, 2);
    }
    if (lua_type(L, 2) == LUA_TSTRING) {
        lua_pushvalue(L, 2);
        lua_rawget(L, lua_upvalueindex(1));
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int node_newindex(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    if (lua_type(L, 2) != LUA_TNUMBER) {
        raise(L, errc::kInvalidArgument, std::format("only elements of a {} can be set (an integer index, not a {})", kind_name(*n), type_name_of(L, 2)),
              n->label);
    }
    return write_at(L, *n, 2, 3);
}

int node_len(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const place p = locate_or_raise(L, *n);
    lua_pushinteger(L, static_cast<lua_Integer>(p.size / elem_size(n->elem)));
    return 1;
}

// for i, v in pairs(span): the elements in order.
int node_next(lua_State* L) {
    view_node& n = self_node(L, "pairs");
    const lua_Integer i = luaL_checkinteger(L, 2) + 1;
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    if (i < 1 || static_cast<lua_Unsigned>(i) > p.size / es) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, i);
    push_elem(L, n.elem, p.data + (static_cast<std::size_t>(i) - 1) * es);
    return 2;
}

int node_pairs(lua_State* L) {
    lua_pushcfunction(L, &node_next);
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 0);
    lua_pushnil(L);
    return 4;
}

int node_eq(lua_State* L) {
    const view_node* a = to_span_node(L, 1);
    const view_node* b = to_span_node(L, 2);
    bool same = false;
    if (a != nullptr && b != nullptr && a->elem == b->elem && a->shape == b->shape) {
        const result<place> pa = locate(*a);
        const result<place> pb = locate(*b);
        same = pa && pb && pa->data == pb->data && pa->size == pb->size;
    }
    lua_pushboolean(L, same ? 1 : 0);
    return 1;
}

int node_gc(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    if (n != nullptr && n->origin == node_origin::kHost && n->source_live) {
        n->source_live = false;
        std::destroy_at(n->source);
    }
    return 0;
}

int span_tostring(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const result<place> p = locate(*n);
    const std::string text =
        p ? std::format("span<{}>: {} elements", elem_name(n->elem), p->size / elem_size(n->elem)) : std::format("span<{}>: gone", elem_name(n->elem));
    lua_pushlstring(L, text.data(), text.size());
    return 1;
}

// ---- methods spans and buffers share -------------------------------------------------------------

// v:get(i)
int seq_get(lua_State* L) {
    return read_at(L, self_node(L, "get"), 2);
}

// v:set(i, value)
int seq_set(lua_State* L) {
    return write_at(L, self_node(L, "set"), 2, 3);
}

// v:slice(i [, j]): elements i..j (inclusive), sharing the memory.
int seq_slice(lua_State* L) {
    view_node& n = self_node(L, "slice");
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    const auto [first, last] = range_args(L, 2, p.size / es, n.label);
    push_part(L, 1, first * es, last - first, n.shape, n.elem);
    return 1;
}

// v:fill(value [, i [, j]])
int seq_fill(lua_State* L) {
    view_node& n = self_node(L, "fill");
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, std::format("the {} is read-only", kind_name(n)), n.label);
    }
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    const auto [first, last] = range_args(L, 3, p.size / es, n.label);
    std::byte converted[8];
    if (const elem_error e = to_elem(L, 2, n.elem, converted); e != elem_error::kNone) {
        raise_elem(L, 2, n.elem, e, std::string{n.label});
    }
    if (last > first && before_write(L, n, p, first * es, (last - first) * es)) {
        for (std::size_t i = first; i < last; ++i) {
            std::memcpy(p.data + i * es, converted, es);
        }
    }
    return 0;
}

// v:copy(source [, pos]): source's elements to v from element pos (default 1). source is a span or
// buffer (elements converted when the kinds differ), a table of numbers, or (into bytes) a string.
int seq_copy(lua_State* L) {
    view_node& n = self_node(L, "copy");
    if (!n.writable) {
        raise(L, errc::kInvalidArgument, std::format("the {} is read-only", kind_name(n)), n.label);
    }
    const lua_Integer pos = luaL_optinteger(L, 3, 1);
    const std::size_t es = elem_size(n.elem);
    // Everything is converted first (into a temporary when needed), so a bad element writes nothing.
    std::size_t count = 0;
    const std::byte* from = nullptr;
    if (view_node* src = to_span_node(L, 2)) {
        const place sp = locate_or_raise(L, *src);
        const std::size_t ses = elem_size(src->elem);
        count = sp.size / ses;
        if (src->elem == n.elem || (is_byte_kind(src->elem) && is_byte_kind(n.elem))) {
            from = sp.data;
        } else {
            auto* tmp = static_cast<std::byte*>(lua_newuserdatauv(L, count * es, 0));
            for (std::size_t i = 0; i < count; ++i) {
                push_elem(L, src->elem, sp.data + i * ses);
                if (const elem_error e = to_elem(L, -1, n.elem, tmp + i * es); e != elem_error::kNone) {
                    raise_elem(L, -1, n.elem, e, std::format("{} (element {})", n.label, i + 1));
                }
                lua_pop(L, 1);
            }
            from = tmp;
        }
    } else if (lua_type(L, 2) == LUA_TSTRING && is_byte_kind(n.elem)) {
        std::size_t len = 0;
        from = reinterpret_cast<const std::byte*>(lua_tolstring(L, 2, &len));
        count = len;
    } else if (lua_type(L, 2) == LUA_TTABLE) {
        count = static_cast<std::size_t>(lua_rawlen(L, 2));
        auto* tmp = static_cast<std::byte*>(lua_newuserdatauv(L, count * es, 0));
        for (std::size_t i = 0; i < count; ++i) {
            lua_rawgeti(L, 2, static_cast<lua_Integer>(i + 1));
            if (const elem_error e = to_elem(L, -1, n.elem, tmp + i * es); e != elem_error::kNone) {
                raise_elem(L, -1, n.elem, e, std::format("{} (element {})", n.label, i + 1));
            }
            lua_pop(L, 1);
        }
        from = tmp;
    } else {
        raise(L, errc::kTypeMismatch, std::format("expected a span, a buffer or a table to copy from, got {}", type_name_of(L, 2)), n.label);
    }
    const place p = locate_or_raise(L, n); // after the source: converting ran no C++, but keep it last
    const std::size_t dest_count = p.size / es;
    if (pos < 1 || static_cast<lua_Unsigned>(pos) - 1 > dest_count || count > dest_count - (static_cast<std::size_t>(pos) - 1)) {
        raise(L, errc::kOutOfRange, std::format("{} elements from {} don't fit [1, {}]", count, pos, dest_count), n.label);
    }
    const std::size_t at = (static_cast<std::size_t>(pos) - 1) * es;
    if (count > 0 && before_write(L, n, p, at, count * es)) {
        std::memmove(p.data + at, from, count * es);
    }
    return 0;
}

// v:totable([i [, j]]): the elements as a new table.
int seq_totable(lua_State* L) {
    view_node& n = self_node(L, "totable");
    const place p = locate_or_raise(L, n);
    const std::size_t es = elem_size(n.elem);
    const auto [first, last] = range_args(L, 2, p.size / es, n.label);
    lua_createtable(L, static_cast<int>(std::min<std::size_t>(last - first, (std::numeric_limits<int>::max)())), 0);
    for (std::size_t i = first; i < last; ++i) {
        push_elem(L, n.elem, p.data + i * es);
        lua_rawseti(L, -2, static_cast<lua_Integer>(i - first + 1));
    }
    return 1;
}

// v:kind(): "f32", "u8", ...
int seq_kind(lua_State* L) {
    const view_node& n = self_node(L, "kind");
    const std::string_view name = elem_name(n.elem);
    lua_pushlstring(L, name.data(), name.size());
    return 1;
}

// v:writable(): whether elements may be set (host memory also needs the patch role).
int seq_writable(lua_State* L) {
    lua_pushboolean(L, self_node(L, "writable").writable ? 1 : 0);
    return 1;
}

// ---- struct views ------------------------------------------------------------------------------------

const field_desc* field_of(lua_State* L, int key) {
    lua_pushvalue(L, key);
    const field_desc* f = lua_rawget(L, lua_upvalueindex(1)) == LUA_TLIGHTUSERDATA ? static_cast<const field_desc*>(lua_touserdata(L, -1)) : nullptr;
    lua_pop(L, 1);
    return f;
}

std::string field_label(const view_node& n, const field_desc& f) {
    return std::format("{}.{}", n.type->name, f.name);
}

// Pushes field f of the struct view at index 1 (`n`), found at `p`.
void push_field(lua_State* L, view_node& n, const place& p, const field_desc& f) {
    auto* at = static_cast<std::byte*>(f.address(p.data));
    switch (f.shape) {
    case field_shape::kValue: push_elem(L, f.elem, at); break;
    case field_shape::kArray: {
        const bool writable = n.writable && f.writable;
        push_part(L, 1, static_cast<std::size_t>(at - p.data), f.count, node_shape::kSpan, f.elem);
        static_cast<view_node*>(lua_touserdata(L, -1))->writable = writable;
        break;
    }
    case field_shape::kObject: {
        const view_type_info* type = f.nested();
        char key[128];
        const std::size_t len = std::min(type->key.size(), sizeof key - 1);
        std::memcpy(key, type->key.data(), len);
        key[len] = '\0';
        view_node* child = new_node(L, 0, key);
        child->shape = node_shape::kObject;
        child->origin = node_origin::kParent;
        child->writable = n.writable && f.writable;
        child->offset = static_cast<std::size_t>(at - p.data);
        child->parent = &n;
        child->type = type;
        child->label = n.label;
        lua_pushvalue(L, 1);
        lua_setiuservalue(L, -2, 1);
        break;
    }
    }
}

// Upvalue 1: the type's fields.
int object_index(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const field_desc* f = field_of(L, 2);
    if (f == nullptr) {
        lua_pushnil(L);
        return 1;
    }
    const place p = locate_or_raise(L, *n);
    push_field(L, *n, p, *f);
    return 1;
}

// Upvalue 1: the type's fields.
int object_newindex(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const field_desc* f = field_of(L, 2);
    if (f == nullptr) {
        size_t len = 0;
        const char* key = luaL_tolstring(L, 2, &len);
        raise(L, errc::kInvalidArgument, std::format("{} has no field '{}'", n->type->name, std::string_view{key, len}), n->label);
    }
    if (f->shape != field_shape::kValue) {
        raise(L, errc::kInvalidArgument, std::format("a {} can't be assigned: set its {}", f->shape == field_shape::kArray ? "array" : "struct", f->shape == field_shape::kArray ? "elements" : "fields"),
              field_label(*n, *f));
    }
    if (!n->writable || !f->writable) {
        raise(L, errc::kInvalidArgument, "is read-only", field_label(*n, *f));
    }
    const place p = locate_or_raise(L, *n);
    std::byte converted[8];
    if (const elem_error e = to_elem(L, 3, f->elem, converted); e != elem_error::kNone) {
        raise_elem(L, 3, f->elem, e, field_label(*n, *f));
    }
    if (f->ranged) {
        const lua_Number v = lua_tonumber(L, 3);
        if (!(v >= f->min && v <= f->max)) { // NaN is outside every range
            raise(L, errc::kOutOfRange, std::format("must lie in [{}, {}]", f->min, f->max), field_label(*n, *f));
        }
    }
    auto* at = static_cast<std::byte*>(f->address(p.data));
    const std::size_t size = elem_size(f->elem);
    if (before_write(L, *n, p, static_cast<std::size_t>(at - p.data), size, f)) {
        std::memcpy(at, converted, size);
    }
    return 0;
}

int object_tostring(lua_State* L) {
    auto* n = static_cast<view_node*>(lua_touserdata(L, 1));
    const result<place> p = locate(*n);
    const std::string text = p ? std::format("{}: {}", n->type->name, static_cast<const void*>(p->data)) : std::format("{}: gone", n->type->name);
    lua_pushlstring(L, text.data(), text.size());
    return 1;
}

// Two views of the same object.
int object_eq(lua_State* L) {
    bool same = false;
    if (lua_type(L, 1) == LUA_TUSERDATA && lua_type(L, 2) == LUA_TUSERDATA && lua_getmetatable(L, 1) != 0 && lua_getmetatable(L, 2) != 0) {
        if (lua_rawequal(L, -1, -2) != 0) {
            const auto* a = static_cast<const view_node*>(lua_touserdata(L, 1));
            const auto* b = static_cast<const view_node*>(lua_touserdata(L, 2));
            const result<place> pa = locate(*a);
            const result<place> pb = locate(*b);
            same = pa && pb && pa->data == pb->data;
        }
    }
    lua_pushboolean(L, same ? 1 : 0);
    return 1;
}

// for name, value in pairs(view): the fields in declaration order.
int object_next(lua_State* L) {
    if (lua_getmetatable(L, 1) == 0 || lua_getfield(L, -1, kOrderField) != LUA_TTABLE) {
        return 0;
    }
    const int order = lua_gettop(L);
    lua_Integer next = 1;
    if (!lua_isnoneornil(L, 2)) {
        const lua_Integer n = static_cast<lua_Integer>(lua_rawlen(L, order));
        next = n + 1; // a key that is no field ends the walk
        for (lua_Integer i = 1; i <= n; ++i) {
            lua_rawgeti(L, order, i);
            const bool found = lua_rawequal(L, -1, 2) != 0;
            lua_pop(L, 1);
            if (found) {
                next = i + 1;
                break;
            }
        }
    }
    if (lua_rawgeti(L, order, next) == LUA_TNIL) {
        return 1; // nil: done
    }
    lua_pushvalue(L, -1);
    lua_gettable(L, 1); // through __index
    return 2;
}

int object_pairs(lua_State* L) {
    lua_pushcfunction(L, &object_next);
    lua_pushvalue(L, 1);
    lua_pushnil(L);
    lua_pushnil(L);
    return 4;
}

bool same_field(const field_desc& a, const field_desc& b) noexcept {
    return a.address == b.address && a.shape == b.shape && a.elem == b.elem && a.writable == b.writable && a.count == b.count &&
           a.ranged == b.ranged && a.min == b.min && a.max == b.max;
}

// Copies a fixed string key into a C string for luaL_* (keys are short).
struct c_key {
    explicit c_key(std::string_view key) noexcept {
        const std::size_t len = std::min(key.size(), sizeof text - 1);
        std::memcpy(text, key.data(), len);
        text[len] = '\0';
    }
    char text[128];
};

} // namespace

// ---- nodes -------------------------------------------------------------------------------------------

view_node* to_span_node(lua_State* L, int index) noexcept {
    if (lua_type(L, index) != LUA_TUSERDATA) {
        return nullptr;
    }
    if (void* n = luaL_testudata(L, index, kSpanKey)) {
        return static_cast<view_node*>(n);
    }
    return static_cast<view_node*>(luaL_testudata(L, index, kBufferKey));
}

result<place> locate(const view_node& n) {
    switch (n.origin) {
    case node_origin::kInline: return place{n.data, n.count, nullptr, nullptr, 0};
    case node_origin::kHost: {
        result<region> r = n.source->resolve();
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return place{r->data, r->size, &n, r->data, r->size};
    }
    case node_origin::kParent: {
        result<place> p = locate(*n.parent);
        if (!p) {
            return p;
        }
        const std::size_t size = n.shape == node_shape::kObject ? n.type->size : n.count * elem_size(n.elem);
        if (n.offset > p->size || size > p->size - n.offset) {
            return fail(errc::kOutOfRange, "the view no longer fits the memory it is part of (it shrank)");
        }
        p->data += n.offset;
        p->size = size;
        return p;
    }
    }
    return fail(errc::kRuntime, "not a view");
}

bool find_place(const view_node& n, place& out) noexcept {
    switch (n.origin) {
    case node_origin::kInline: out = place{n.data, n.count, nullptr, nullptr, 0}; return true;
    case node_origin::kHost: {
        region r;
        if (!n.source->find(r)) {
            return false;
        }
        out = place{r.data, r.size, &n, r.data, r.size};
        return true;
    }
    case node_origin::kParent: {
        if (!find_place(*n.parent, out)) {
            return false;
        }
        const std::size_t size = n.shape == node_shape::kObject ? n.type->size : n.count * elem_size(n.elem);
        if (n.offset > out.size || size > out.size - n.offset) {
            return false;
        }
        out.data += n.offset;
        out.size = size;
        return true;
    }
    }
    return false;
}

place locate_or_raise(lua_State* L, const view_node& n) {
    place found;
    if (find_place(n, found)) [[likely]] {
        return found;
    }
    // Asked again for the reason (the binding is a lookup: calling it twice changes nothing).
    result<place> p = locate(n);
    if (!p) {
        error err = std::move(p).error();
        if (err.where.empty()) {
            err.where = std::string{n.label};
        }
        raise(L, std::move(err));
    }
    return *p;
}

bool before_write(lua_State* L, view_node& writer, const place& p, std::size_t offset, std::size_t len, const field_desc* field) {
    if (p.root == nullptr) {
        return true; // a script's own buffer
    }
    const stack s{L};
    context& ctx = s.context();
    const auto what = [&] { return field != nullptr ? field_label(writer, *field) : std::string{writer.label}; };
    // A node that journaled in this sandbox already passed the check (the role is the sandbox's).
    if (writer.cache.ctx != &ctx && !allows(ctx.caller_role(), role::kPatch)) {
        raise(L, errc::kForbidden, std::format("writing host memory needs role {}", role::kPatch), what());
    }
    std::optional<error> failed;
    bool ok = false;
    try {
        ok = journal_touch(ctx, writer.cache, p, static_cast<std::size_t>(p.data - p.root_data) + offset, len);
    } catch (const std::exception& e) {
        failed = make_error(errc::kMemoryExceeded, std::format("journaling the write failed: {}", e.what()), what());
    }
    if (failed) {
        raise(L, std::move(*failed));
    }
    return ok;
}

void push_elem(lua_State* L, elem_kind k, const std::byte* p) {
    switch (k) {
    case elem_kind::kI8: lua_pushinteger(L, load<std::int8_t>(p)); break;
    case elem_kind::kU8:
    case elem_kind::kByte: lua_pushinteger(L, load<std::uint8_t>(p)); break;
    case elem_kind::kI16: lua_pushinteger(L, load<std::int16_t>(p)); break;
    case elem_kind::kU16: lua_pushinteger(L, load<std::uint16_t>(p)); break;
    case elem_kind::kI32: lua_pushinteger(L, load<std::int32_t>(p)); break;
    case elem_kind::kU32: lua_pushinteger(L, static_cast<lua_Integer>(load<std::uint32_t>(p))); break;
    case elem_kind::kI64: lua_pushinteger(L, static_cast<lua_Integer>(load<std::int64_t>(p))); break;
    case elem_kind::kU64: {
        const auto v = load<std::uint64_t>(p);
        if (v > static_cast<std::uint64_t>((std::numeric_limits<lua_Integer>::max)())) {
            lua_pushnumber(L, static_cast<lua_Number>(v)); // as marshal pushes it
        } else {
            lua_pushinteger(L, static_cast<lua_Integer>(v));
        }
        break;
    }
    case elem_kind::kF32: lua_pushnumber(L, static_cast<lua_Number>(load<float>(p))); break;
    case elem_kind::kF64: lua_pushnumber(L, static_cast<lua_Number>(load<double>(p))); break;
    case elem_kind::kBool: lua_pushboolean(L, load<std::uint8_t>(p) != 0 ? 1 : 0); break; // a bool's byte, never read as bool
    }
}

elem_error to_elem(lua_State* L, int index, elem_kind k, std::byte* out) noexcept {
    if (k == elem_kind::kBool) {
        if (lua_type(L, index) != LUA_TBOOLEAN) {
            return elem_error::kType;
        }
        store<bool>(out, lua_toboolean(L, index) != 0);
        return elem_error::kNone;
    }
    if (lua_type(L, index) != LUA_TNUMBER) {
        return elem_error::kType;
    }
    if (k == elem_kind::kF32) {
        store<float>(out, static_cast<float>(lua_tonumber(L, index)));
        return elem_error::kNone;
    }
    if (k == elem_kind::kF64) {
        store<double>(out, static_cast<double>(lua_tonumber(L, index)));
        return elem_error::kNone;
    }
    int is_integer = 0;
    const lua_Integer v = lua_tointegerx(L, index, &is_integer); // 2.0 converts, 1.5 doesn't
    if (is_integer == 0) {
        return elem_error::kNotInteger;
    }
    if (!integer_fits(k, v)) {
        return elem_error::kRange;
    }
    switch (k) {
    case elem_kind::kI8: store(out, static_cast<std::int8_t>(v)); break;
    case elem_kind::kU8:
    case elem_kind::kByte: store(out, static_cast<std::uint8_t>(v)); break;
    case elem_kind::kI16: store(out, static_cast<std::int16_t>(v)); break;
    case elem_kind::kU16: store(out, static_cast<std::uint16_t>(v)); break;
    case elem_kind::kI32: store(out, static_cast<std::int32_t>(v)); break;
    case elem_kind::kU32: store(out, static_cast<std::uint32_t>(v)); break;
    case elem_kind::kI64: store(out, static_cast<std::int64_t>(v)); break;
    case elem_kind::kU64: store(out, static_cast<std::uint64_t>(v)); break;
    default: break;
    }
    return elem_error::kNone;
}

void raise_elem(lua_State* L, int index, elem_kind k, elem_error e, std::string where) {
    switch (e) {
    case elem_error::kType:
        raise(L, make_error(errc::kTypeMismatch,
                            std::format("expected {}, got {}", k == elem_kind::kBool ? "boolean" : (is_float_kind(k) ? "number" : "integer"), type_name_of(L, index)),
                            std::move(where)));
    case elem_error::kNotInteger: raise(L, make_error(errc::kOutOfRange, std::format("{} is not an integer", lua_tonumber(L, index)), std::move(where)));
    case elem_error::kRange:
        raise(L, make_error(errc::kOutOfRange, std::format("{} does not fit {}", lua_tointeger(L, index), elem_name(k)), std::move(where)));
    case elem_error::kNone: break;
    }
    raise(L, make_error(errc::kRuntime, "bad element", std::move(where)));
}

view_node* new_node(lua_State* L, std::size_t payload, const char* key) {
    void* memory = lua_newuserdatauv(L, kNodeSize + payload, 1);
    auto* n = std::construct_at(static_cast<view_node*>(memory));
    luaL_setmetatable(L, key);
    return n;
}

std::byte* node_payload(view_node* node) noexcept {
    return reinterpret_cast<std::byte*>(node) + kNodeSize;
}

void push_part(lua_State* L, int index, std::size_t offset, std::size_t count, node_shape shape, elem_kind elem) {
    index = lua_absindex(L, index);
    auto* parent = static_cast<view_node*>(lua_touserdata(L, index));
    view_node* child = new_node(L, 0, shape == node_shape::kBytes ? kBufferKey : kSpanKey);
    child->shape = shape;
    child->origin = node_origin::kParent;
    child->elem = shape == node_shape::kBytes ? elem_kind::kU8 : elem;
    child->writable = parent->writable;
    child->offset = offset;
    child->count = count;
    child->parent = parent;
    child->label = parent->label;
    lua_pushvalue(L, index);
    lua_setiuservalue(L, -2, 1); // keeps the parent (and its memory) alive
}

bool read_span_arg(lua_State* L, int index, arg_slot& out) noexcept {
    try {
        if (lua_type(L, index) == LUA_TSTRING) {
            std::size_t len = 0;
            out.view.data = lua_tolstring(L, index, &len);
            out.view.size = len;
            out.view.elem = static_cast<std::uint8_t>(elem_kind::kU8);
            out.view.string = true;
            return true;
        }
        const view_node* n = to_span_node(L, index);
        place p;
        if (n == nullptr || !find_place(*n, p)) {
            return false; // the general path raises the error
        }
        out.view.data = p.data;
        out.view.size = p.size;
        out.view.elem = static_cast<std::uint8_t>(n->elem);
        out.view.string = false;
        return true;
    } catch (const std::exception&) { // making the error (the general path makes it again)
        return false;
    }
}

std::pair<std::size_t, std::size_t> range_args(lua_State* L, int i_index, std::size_t count, std::string_view where) {
    const lua_Integer i = luaL_optinteger(L, i_index, 1);
    const lua_Integer j = luaL_optinteger(L, i_index + 1, static_cast<lua_Integer>(count));
    if (i < 1 || static_cast<lua_Unsigned>(i) > count + 1 || j < i - 1 || static_cast<lua_Unsigned>(j) > count) {
        raise(L, errc::kOutOfRange, std::format("range [{}, {}] out of range [1, {}]", i, j, count), where);
    }
    return {static_cast<std::size_t>(i) - 1, static_cast<std::size_t>(j)};
}

namespace {

// Typed views index elements (a C __index: integers are elements, names methods).
void set_span_metamethods(lua_State* L, int mt, int methods) {
    lua_pushcfunction(L, &node_gc); // a host view owns its source
    lua_setfield(L, mt, "__gc");
    lua_pushvalue(L, methods);
    lua_pushcclosure(L, &node_index, 1);
    lua_setfield(L, mt, "__index");
    lua_pushcfunction(L, &node_newindex);
    lua_setfield(L, mt, "__newindex");
    lua_pushcfunction(L, &node_pairs);
    lua_setfield(L, mt, "__pairs");
    const luaL_Reg span_only[] = {
        {"get", &seq_get},
        {"set", &seq_set},
        {"totable", &seq_totable},
        {"kind", &seq_kind},
        {"writable", &seq_writable},
        {nullptr, nullptr},
    };
    for (const luaL_Reg* r = span_only; r->name != nullptr; ++r) {
        lua_pushcfunction(L, r->func);
        lua_setfield(L, methods, r->name);
    }
}

// Buffers are read and written through methods: __index is the methods table itself (a method
// lookup is the VM's table lookup, no C call); b[i] = v raises.
int buffer_newindex(lua_State* L) {
    raise(L, errc::kInvalidArgument, "a buffer is read and written through its methods (b:write_u8(pos, v)) or a view (b:view(\"u8\")[i] = v)",
          "rhp.buffer");
}

} // namespace

void set_sequence_metamethods(lua_State* L, int mt, int methods, bool buffer) {
    mt = lua_absindex(L, mt);
    methods = lua_absindex(L, methods);
    if (buffer) {
        lua_pushvalue(L, methods);
        lua_setfield(L, mt, "__index");
        lua_pushcfunction(L, &buffer_newindex);
        lua_setfield(L, mt, "__newindex");
    } else {
        set_span_metamethods(L, mt, methods);
    }
    lua_pushcfunction(L, &node_len);
    lua_setfield(L, mt, "__len");
    lua_pushcfunction(L, &node_eq);
    lua_setfield(L, mt, "__eq");
    lua_pushliteral(L, "locked");
    lua_setfield(L, mt, "__metatable");
    const luaL_Reg shared[] = {
        {"slice", &seq_slice},
        {"fill", &seq_fill},
        {"copy", &seq_copy},
        {nullptr, nullptr},
    };
    for (const luaL_Reg* r = shared; r->name != nullptr; ++r) {
        lua_pushcfunction(L, r->func);
        lua_setfield(L, methods, r->name);
    }
}

void define_span_type(lua_State* L) {
    if (luaL_newmetatable(L, kSpanKey) == 0) {
        lua_pop(L, 1);
        return;
    }
    const int mt = lua_gettop(L);
    lua_pushliteral(L, "span");
    lua_setfield(L, mt, "__name");
    lua_pushcfunction(L, &span_tostring);
    lua_setfield(L, mt, "__tostring");
    lua_createtable(L, 0, 8);
    set_sequence_metamethods(L, mt, -1, false);
    lua_pop(L, 2);
}

} // namespace Rhp::script::detail

namespace Rhp::script {

using detail::locate;
using detail::node_origin;
using detail::node_shape;
using detail::view_node;

// ---- stack members ---------------------------------------------------------------------------------

void* stack::push_host_view(const detail::host_view_init& init) const {
    const detail::c_key key{init.shape == detail::view_shape::kSpan ? std::string_view{detail::kSpanKey} : init.type->key};
    view_node* n = detail::new_node(state_, init.source_size, key.text);
    n->shape = init.shape == detail::view_shape::kSpan ? node_shape::kSpan : node_shape::kObject;
    n->origin = node_origin::kHost;
    n->elem = init.elem;
    n->writable = init.writable;
    n->type = init.type;
    // The label lives in uservalue 1 (a Lua string does not move).
    lua_pushlstring(state_, init.label.data(), init.label.size());
    std::size_t len = 0;
    const char* label = lua_tolstring(state_, -1, &len);
    n->label = std::string_view{label, len};
    lua_setiuservalue(state_, -2, 1);
    return detail::node_payload(n);
}

void stack::attach_view_source(detail::view_source* source) const {
    auto* n = static_cast<view_node*>(lua_touserdata(state_, -1));
    n->source = source;
    n->source_live = true;
    result<detail::region> first = source->resolve();
    if (!first) {
        if (n->shape == node_shape::kObject && first.error().code == errc::kStaleHandle) {
            lua_pop(state_, 1); // no object: nil (the view is collected, its source with it)
            lua_pushnil(state_);
            return;
        }
        error err = std::move(first).error();
        if (err.where.empty()) {
            err.where = std::string{n->label};
        }
        raise(err);
    }
}

result<detail::span_arg> stack::to_span(int index, const detail::span_request& request) const {
    lua_State* L = state_;
    const auto mismatch = [&] {
        return fail(errc::kTypeMismatch, std::format("expected span<{}>{}, got {}", elem_name(request.elem), request.bytes ? " (or a buffer)" : "",
                                                     lua_type(L, index) == LUA_TUSERDATA && detail::to_span_node(L, index) != nullptr
                                                         ? std::format("span<{}>", elem_name(detail::to_span_node(L, index)->elem))
                                                         : std::string{type_name(index)}));
    };
    if (lua_type(L, index) == LUA_TSTRING) {
        if (!request.bytes || request.writable) {
            return mismatch();
        }
        std::size_t len = 0;
        const char* data = lua_tolstring(L, index, &len);
        return detail::span_arg{const_cast<char*>(data), len}; // read-only: a std::span<const T>
    }
    if (view_node* n = detail::to_span_node(L, index)) {
        if (!(n->elem == request.elem || (request.bytes && is_byte_kind(n->elem)))) {
            return mismatch();
        }
        result<detail::place> p = locate(*n);
        if (!p) {
            return std::unexpected{std::move(p).error()};
        }
        // A buffer viewed at any byte position may be misaligned: Lua reads it by copying, but a
        // std::span<T> must point at aligned elements.
        if (reinterpret_cast<std::uintptr_t>(p->data) % elem_size(request.elem) != 0) {
            return fail(errc::kInvalidArgument, std::format("a span<{}> given to C++ must be aligned to {} bytes: view the buffer at a position {} bytes apart from its start", elem_name(request.elem),
                                                            elem_size(request.elem), elem_size(request.elem)));
        }
        if (request.writable) {
            if (!n->writable) {
                return fail(errc::kInvalidArgument, std::format("the {} is read-only", n->shape == node_shape::kBytes ? "buffer" : "span"));
            }
            if (p->root != nullptr) {
                // C++ may write any of it: journaled first, like a script's writes.
                detail::context& ctx = context();
                if (!allows(ctx.caller_role(), role::kPatch)) {
                    return fail(errc::kForbidden, std::format("passing host memory to be written needs role {}", role::kPatch));
                }
                bool ok = false;
                try {
                    ok = detail::journal_touch(ctx, n->cache, *p, static_cast<std::size_t>(p->data - p->root_data), p->size);
                } catch (const std::exception& e) {
                    return fail(errc::kMemoryExceeded, std::format("journaling the span failed: {}", e.what()));
                }
                if (!ok) {
                    return fail(errc::kUnloaded, "the sandbox is closing");
                }
            }
        }
        return detail::span_arg{p->data, p->size / elem_size(request.elem)};
    }
    if (request.tables && lua_type(L, index) == LUA_TTABLE) {
        // A copy for the call, left on the stack (memory counted like any Lua value).
        const std::size_t count = static_cast<std::size_t>(lua_rawlen(L, index));
        const std::size_t es = elem_size(request.elem);
        auto* tmp = static_cast<std::byte*>(lua_newuserdatauv(L, count * es, 0));
        for (std::size_t i = 0; i < count; ++i) {
            lua_rawgeti(L, index, static_cast<lua_Integer>(i + 1));
            const detail::elem_error e = detail::to_elem(L, -1, request.elem, tmp + i * es);
            if (e != detail::elem_error::kNone) {
                result<detail::span_arg> bad = fail(e == detail::elem_error::kType ? errc::kTypeMismatch : errc::kOutOfRange,
                                                    std::format("element {}: {}", i + 1,
                                                                e == detail::elem_error::kType ? std::format("expected a number, got {}", type_name(-1))
                                                                : e == detail::elem_error::kNotInteger
                                                                    ? std::format("{} is not an integer", lua_tonumber(L, -1))
                                                                    : std::format("{} does not fit {}", lua_tointeger(L, -1), elem_name(request.elem))));
                lua_pop(L, 1);
                return bad;
            }
            lua_pop(L, 1);
        }
        return detail::span_arg{tmp, count};
    }
    return mismatch();
}

result<void*> stack::to_object(int index, std::string_view key, std::string_view name, bool nil_ok) const {
    if (nil_ok && lua_isnoneornil(state_, index)) {
        return nullptr;
    }
    const detail::c_key k{key};
    auto* n = static_cast<view_node*>(luaL_testudata(state_, index, k.text));
    if (n == nullptr) {
        return fail(errc::kTypeMismatch, std::format("expected {}, got {}", name, type_name(index)));
    }
    result<detail::place> p = locate(*n);
    if (!p) {
        return std::unexpected{std::move(p).error()};
    }
    return static_cast<void*>(p->data);
}

result<void> stack::define_view_type(const detail::view_type_info& type, const detail::field_desc* fields, std::size_t count) const {
    lua_State* L = state_;
    const detail::c_key key{type.key};
    if (luaL_getmetatable(L, key.text) != LUA_TNIL) {
        // Defined by another lib: the same C++ type, and fields that agree with the ones it has.
        const int mt = lua_gettop(L);
        lua_getfield(L, mt, detail::kTypeTagField);
        const bool same_type = lua_touserdata(L, -1) == type.type_tag;
        lua_pop(L, 1);
        if (!same_type) {
            lua_pop(L, 1);
            return fail(errc::kAlreadyLoaded, std::format("view type '{}' is already defined for a different C++ type", type.name));
        }
        lua_getfield(L, mt, detail::kFieldsField);
        lua_getfield(L, mt, detail::kOrderField);
        const int table = mt + 1;
        const int order = mt + 2;
        for (std::size_t i = 0; i < count; ++i) {
            lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
            if (lua_rawget(L, table) == LUA_TLIGHTUSERDATA &&
                !detail::same_field(*static_cast<const detail::field_desc*>(lua_touserdata(L, -1)), fields[i])) {
                lua_settop(L, mt - 1);
                return fail(errc::kAlreadyLoaded, std::format("view type '{}' already has a field named '{}' declared differently", type.name, fields[i].name));
            }
            lua_pop(L, 1);
        }
        for (std::size_t i = 0; i < count; ++i) {
            lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
            if (lua_rawget(L, table) == LUA_TNIL) {
                lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
                lua_pushlightuserdata(L, const_cast<detail::field_desc*>(&fields[i]));
                lua_rawset(L, table);
                lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
                lua_rawseti(L, order, static_cast<lua_Integer>(lua_rawlen(L, order)) + 1);
            }
            lua_pop(L, 1);
        }
        lua_settop(L, mt - 1);
        return {};
    }
    lua_pop(L, 1);
    luaL_newmetatable(L, key.text);
    const int mt = lua_gettop(L);
    lua_pushlstring(L, type.name.data(), type.name.size());
    lua_setfield(L, mt, "__name");
    lua_pushlightuserdata(L, const_cast<void*>(type.type_tag));
    lua_setfield(L, mt, detail::kTypeTagField);
    lua_pushboolean(L, 1);
    lua_setfield(L, mt, detail::kViewMarker);
    lua_createtable(L, 0, static_cast<int>(count));
    const int table = lua_gettop(L);
    lua_createtable(L, static_cast<int>(count), 0);
    const int order = lua_gettop(L);
    for (std::size_t i = 0; i < count; ++i) {
        lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
        lua_pushlightuserdata(L, const_cast<detail::field_desc*>(&fields[i]));
        lua_rawset(L, table);
        lua_pushlstring(L, fields[i].name.data(), fields[i].name.size());
        lua_rawseti(L, order, static_cast<lua_Integer>(i + 1));
    }
    lua_pushvalue(L, order);
    lua_setfield(L, mt, detail::kOrderField);
    lua_pushvalue(L, table);
    lua_setfield(L, mt, detail::kFieldsField);
    lua_pushvalue(L, table);
    lua_pushcclosure(L, &detail::object_index, 1);
    lua_setfield(L, mt, "__index");
    lua_pushvalue(L, table);
    lua_pushcclosure(L, &detail::object_newindex, 1);
    lua_setfield(L, mt, "__newindex");
    lua_pushcfunction(L, &detail::object_tostring);
    lua_setfield(L, mt, "__tostring");
    lua_pushcfunction(L, &detail::object_eq);
    lua_setfield(L, mt, "__eq");
    lua_pushcfunction(L, &detail::object_pairs);
    lua_setfield(L, mt, "__pairs");
    lua_pushcfunction(L, &detail::node_gc);
    lua_setfield(L, mt, "__gc");
    lua_pushliteral(L, "locked");
    lua_setfield(L, mt, "__metatable");
    lua_settop(L, mt - 1);
    return {};
}

} // namespace Rhp::script
