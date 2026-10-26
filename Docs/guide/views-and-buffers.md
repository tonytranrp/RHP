# Typed views, struct views and buffers

Bindings normally copy: a `std::vector<float>` result becomes a new Lua table, a struct becomes a table through `Rhp::convert`. For arrays and objects a script works on in place (a height map, particle data, a transform), RHP hands Lua a **view** of the C++ memory instead: no copy into a table, element and field reads and writes go straight to the bytes, and every script write is **journaled**, so reverting the module puts the bytes back. Scripts also get **byte buffers** of their own (`rhp.buffer`) for binary data.

## A complete example

```cpp
#include <array>
#include <cstdint>
#include <numeric>
#include <span>
#include <unordered_map>
#include <unordered_set>

#include <rhp/rhp.hpp>

namespace game {

struct vec3 {
    float x = 0;
    float y = 0;
    float z = 0;
};

struct transform { // a view type: standard layout
    vec3 position;
    float scale[3] = {1, 1, 1};
    std::int32_t layer = 0;
    std::uint32_t id = 0;
};

struct entity_id {
    std::uint32_t value = 0;
    bool operator==(const entity_id&) const = default;
};

std::unordered_set<std::uint32_t> entities;
std::unordered_map<std::uint32_t, transform> transforms;
std::array<float, 256> heights{};

bool is_alive(const entity_id& e) {
    return entities.contains(e.value);
}

entity_id find(std::uint32_t id) {
    return entity_id{id};
}

transform* transform_of(entity_id e) { // nullptr when there is none: the script gets nil
    const auto it = transforms.find(e.value);
    return it != transforms.end() ? &it->second : nullptr;
}

std::span<float> height_map() {
    return heights;
}

float average(std::span<const float> values) {
    return values.empty() ? 0.0f : std::accumulate(values.begin(), values.end(), 0.0f) / static_cast<float>(values.size());
}

using lib = Rhp::lib<"game">
    ::handle<"entity", entity_id, &is_alive>
    ::fn<"find", &find>
    ::view<"vec3", vec3>
    ::field<"x", &vec3::x>::field<"y", &vec3::y>::field<"z", &vec3::z>
    ::view<"transform", transform>
    ::field<"position", &transform::position>           // a nested view
    ::field<"scale", &transform::scale>                 // an array: a typed view
    ::field<"layer", &transform::layer, Rhp::range<0, 31>>
    ::ro_field<"id", &transform::id>
    ::property<"transform", &transform_of>              // e.transform
    ::fn<"height_map", &height_map>                     // a typed view of the array
    ::fn<"average", &average>;                          // takes a view, a buffer view or a table

} // namespace game
```

```lua
local t = game.find(7).transform      -- nil if entity 7 has no transform
t.position.y = t.position.y + 1       -- in place, journaled
t.scale[2] = 2
t.layer = 3                           -- t.layer = 40 raises: [out_of_range] transform.layer: must lie in [0, 31]

local h = game.height_map()
for i = 1, #h do h[i] = h[i] * 0.5 end -- 256 writes, one journal entry
print(game.average(h))                -- C++ reads the same memory: no copy

local b = rhp.buffer.new(16)          -- bytes this script owns
local pos = b:write_u32(1, 0xCAFE, "be")
local f = b:view("f32", pos, 2)       -- two floats over bytes 5..12
f[1], f[2] = 1.5, 2.5
print(game.average(f), b:read_u16(3, "be"))
```

Unloading or reverting the module puts `heights`, the transform's `position.y`, `scale[1]` and anything else the script wrote back to what they were; the buffer is the script's own and simply goes away.

## Typed views: `std::span<T>`

A binding (function, method or property) returning `std::span<T>` gives Lua a typed view; `std::span<const T>` a read-only one. `T` is any arithmetic type but `bool`, or `std::byte` (anything else doesn't compile).

| In Lua | |
|---|---|
| `v[i]`, `v:get(i)` | element `i` (1-based); outside `[1, #v]` raises `kOutOfRange` with the binding's label |
| `v[i] = x`, `v:set(i, x)` | needs a writable view (and, for C++ memory, the patch role: `kForbidden` otherwise); integers must fit the element type (`kOutOfRange`), floats are converted |
| `#v`, `pairs(v)` | the length; the elements in order (`ipairs` stops with an error at `#v + 1`: use `pairs` or `for i = 1, #v`) |
| `v:slice(i [, j])` | elements `i..j` sharing the memory (bounds fixed when sliced) |
| `v:fill(x [, i [, j]])`, `v:copy(src [, pos])` | bulk writes: one journal check for the whole range; `src` is a span (converted element by element when the types differ), a buffer or a table, checked before anything is written |
| `v:totable([i [, j]])`, `v:kind()`, `v:writable()` | a copy as a table; `"f32"`, `"u8"`, ...; whether elements may be set |

Elements are read as Lua integers (`u64` above `2^63 - 1` as a float, like other bindings) or floats.

**Spans as parameters.** `std::span<const T>` takes a typed view of exactly `T` (no conversion: the point is no copy), a table of numbers (copied for the call into Lua memory), and for one-byte `T` (`std::byte`, `char`, `std::uint8_t`, ...) also a buffer, a byte view or a Lua string. `std::span<T>` (C++ writes) takes a writable typed view or buffer: when the view is of C++ memory, its whole range is journaled before the call (patch role), so what C++ writes is undone with the script. The span is valid during the call only. A binding with `Rhp::undo<G>` fed its arguments gets a copy of a span's elements (as a `std::vector`, which converts back to a span).

## Struct views: `::view` and `::field`

`::view<"name", T>` declares a struct view type (a standard-layout class; a polymorphic or otherwise non-standard-layout type doesn't compile). Each `::field<"name", &T::member, tags...>` is a field of the view type its member pointer belongs to; `::ro_field<>` is read-only (so is a `const` member). A binding returning `T*`, `T&` (or `const`: a read-only view) of a declared view type gives Lua a view of that object; `nullptr` gives `nil`.

| Field type | In Lua |
|---|---|
| a number, `bool` or enum | `t.f` reads it, `t.f = x` writes it (patch role, journaled); number fields take the variable tags, `Rhp::range<>` enforced on writes; enums are integers |
| a C array or `std::array` of span elements | a typed view: `t.m[3] = 1` |
| a struct of another declared view type | a nested view: `t.position.x = 1`; assigning the whole struct raises (set its fields) |

`pairs(t)` walks the fields in declaration order; `==` is true for two views of the same object. A struct view passes to a parameter of its type by value, `const T&` or `const T*` (nil: `nullptr`).

## Lifetime: a view keeps no pointer

A view remembers its binding and the arguments it was called with, and **calls the binding again on every access** (handle arguments are checked with their `is_alive` first). So a script may keep a view across frames: when the vector grew it reads the new memory, when the entity died it raises `kStaleHandle`, when the binding now returns `nullptr` it raises `kStaleHandle` too, and it never reads freed memory. What a binding returns must stay valid until the binding is called again; a binding returning a view is a lookup, so it can't be tagged `undo<>` / `irreversible` or return `Rhp::async<T>`, and its parameters own their data (no spans or views). Slices and field views find their parent the same way and raise `kOutOfRange` when the parent shrank below them.

Re-resolving costs one call of the binding per access: cheap for a global or a hash lookup, worth holding a local for in hot loops (`local h = game.height_map()` once, then index it).

## Undo

Writes to C++ memory are journaled per **view target** (one binding with one set of arguments) and per running code (a module's request, a handler call): the first write makes one journal entry, and each element (for spans; byte, for struct fields) keeps its original the first time that entry writes it. So a loop writing 10k floats costs one entry and one copy per element touched, not 10k entries. Reverting the module, a failed request, `revert_to` and `revert_all` put those bytes back where the memory is now. Entries of different modules writing the same target stack like variable writes: reverted in any order, every element ends up as if the reverted writes never happened. Read-only views journal nothing, and nor do buffers.

## Buffers: `rhp.buffer`

| | |
|---|---|
| `rhp.buffer.new(size [, fill])`, `rhp.buffer.from(bytes)` | a zeroed (or filled) buffer; a copy of a string, a buffer or a span's bytes |
| `b[i]`, `#b`, and the span methods | bytes as integers 0..255 |
| `b:read_<k>(pos [, order])`, `b:write_<k>(pos, x [, order])` | `k` is `i8 u8 i16 u16 i32 u32 i64 u64 f32 f64`; `pos` is a 1-based byte position; `order` `"le"` (default) or `"be"`; writes return the position after them |
| `b:read_string(pos, len)`, `b:write_string(pos, s)`, `b:tostring([i [, j]])` | bytes as strings |
| `b:pack(pos, fmt, ...)`, `b:unpack(pos, fmt)` | `string.pack` / `string.unpack` formats at a position (`unpack` returns the values, then the position after them) |
| `b:slice(i [, j])`, `b:view(kind [, pos [, count]])` | a buffer or a typed view sharing the bytes (no alignment needed) |

A buffer is script state like a table: its memory is a Lua allocation (counted in `limits.memory`), never journaled, and it lives as long as something refers to it.

## Tools and `RHP_ENABLE=OFF`

Stubs annotate spans as `rhp.span<number>` / `rhp.span<integer>`, struct views as a `---@class` per view type with its fields, and `rhp.buffer`; `api()` lists view types under `views`. `Rhp::test::fake<L>` keeps view types and fields; its view bindings return an empty span, `nil` or one default object. With `RHP_ENABLE=OFF` the DSL, `api::describe` and the stubs still build; nothing runs (`install` reports `kDisabled`).

The design, the undo strategy and what was measured are in [the decision](../decisions/views-and-buffers.md); numbers in [benchmarks](../benchmarks.md#typed-views-struct-views-and-buffers).
