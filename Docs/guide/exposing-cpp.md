# Exposing C++ to Lua

Bindings describe the application capabilities available to scripts. Names and tag combinations are checked on the declaration line; argument/result conversions and the complete handle tree are checked by `install<Lib>()`. The examples below assume the referenced C++ functions and variables are already declared.

## `Rhp::lib`: functions, variables, handles

```cpp
using game_lib = Rhp::lib<"game">                                                                      // Lua sees the global `game`
    ::fn<"spawn", &game::spawn, Rhp::undo<&game::despawn>>                                             // reversible, needs patch role
    ::fn<"find", &game::find>                                                                          // pure, observe role
    ::fn<"explode", &game::explode, Rhp::irreversible>                                                 // allowed, but counted in revert reports
    ::fn<"wipe", &game::wipe, Rhp::requires_role<Rhp::role::kAdmin>>::var<"gravity", &game::g_gravity> // read: observe, write: patch (journaled)
    ::ro<"tick", &game::g_tick>                                                                        // read only
    ::handle<"entity", game::entity_id, &game::is_alive>                                               // opaque userdata + validity check
    ::sub<Rhp::lib<"debug">::fn<"dump", &game::dump_state>>;                                           // game.debug.dump()

host.install<game_lib>(); // or sandbox.install<game_lib>()
```

| Entry | Meaning |
|---|---|
| `fn<"name", &f, tags...>` | a free function (not a member function). Arguments and result cross through `Rhp::convert` |
| `var<"name", &v>` | a writable global variable. Writes are recorded in the undo ledger |
| `ro<"name", &v>` | a read-only variable (a `const` object is fine) |
| `handle<"name", H, &is_alive>` | `H` is a trivially copyable, equality-comparable, non-arithmetic type (a strong id). Lua gets opaque userdata. A stale handle raises `kStaleHandle` instead of returning nil |
| `sub<Lib>` | nests another lib under this one |

Names must be Lua identifiers and unique inside the lib.

**Tags on `fn`** (at most one of `undo` / `irreversible`, at most one `requires_role`):

| Tag | Effect |
|---|---|
| none | pure: observe role may call it. Anything unmarked is *assumed* pure |
| `Rhp::undo<&g>` | changes state, `g` takes it back. `g` is fed the binding's result (a `Rhp::result<>` is unwrapped), or failing that its arguments. Needs patch role |
| `Rhp::irreversible` | changes state and cannot be taken back. Needs patch role; each call is reported as irreversible when reverted |
| `Rhp::requires_role<R>` | override the derived role. Use it to raise the requirement; assigning observe to a mutating function would explicitly grant that mutation to observe callers |

Rules of the road:

- `host.install<Lib>()` registers a lib for current and future identity sandboxes; `box.install<Lib>()` installs it into that one local sandbox. Install host libs before the first `pump()`. Use names that do not collide with Lua globals. Duplicate host registrations return `kAlreadyLoaded`; installation failures within identity sandboxes are logged by the host.
- The lib proxy is locked: writing an unknown, function or `ro` member raises `kInvalidArgument`; reading an unknown member gives `nil`.
- A C++ exception thrown by a binding becomes a Lua error; the original `Rhp::error` comes back to C++ callers.
- A bound function must return. Lua's instruction hook cannot interrupt a long C++ call. Application-owned variables, handle storage and function dependencies must outlive every sandbox that uses them; RHP does not synchronize application access to those variables.
- Arguments may be values or const references; mutable reference parameters and reference results are rejected by `installable`. `std::string_view` arguments borrow Lua storage for the binding call only: copy them if retained. A patch point's default must return an owning value (`std::string`, not `std::string_view` or `const char*`): a Lua override's result lives in a Lua string that is unrooted once the handler returns, so borrowed results are rejected at compile time.

An inverse must undo exactly the recorded operation. For a void-returning binding, the inverse can receive the original arguments:

```cpp
int score = 0;
void add_score(int points) {
    score += points;
}
void remove_score(int points) {
    score -= points;
}

using score_lib = Rhp::lib<"score">::fn<"add", &add_score, Rhp::undo<&remove_score>>;
```

Each successful `score.add(10)` records its own `remove_score(10)`. Resetting all score to zero would also erase unrelated changes, so it is not the inverse of one addition. Result-fed undo is preferred when the inverse accepts the result; argument-fed undo is the fallback. A returned `Rhp::result<T>` error is not journaled as a successful effect. Tuples return multiple Lua values; `result<void>` returns none on success.

## Patch points: overridable call sites

```cpp
float default_damage(float base, int) {
    return base;
}
inline constexpr Rhp::patch_point<"combat.damage", &default_damage> damage{};

float d = damage(base, target); // use it exactly like the function
```

Scripts replace or wrap it, and the override disappears with its module:

```lua
rhp.patch("combat.damage", function(original, base, target)
    return original(base, target) * 2
end)
```

- Needs patch role. Ids are dotted lowercase; one point type per id; the default is a function pointer or captureless lambda.
- Overrides stack (newest on top) and can be reverted in any order.
- Cost while nothing is patched: one atomic load. With `RHP_ENABLE=OFF` it is a direct call.
- A call selects the newest layer owned by the calling thread; layers installed by other threads are skipped and counted by `off_thread_misses()`. Keep installation, Lua use and teardown on the same application thread. The point/event registries and variable-layer metadata are process-wide, so hosts are not isolated from shared application targets.
- If a handler errors, the call falls back to the next layer (or the default); the fault is processed by the sandbox, normally on the next `pump()`.
- `original(...)` calls the next applicable layer or default. Do not save it for later: its call token expires when the handler returns. A patch handler cannot suspend with `rhp.wait`, `rhp.sleep` or `rhp.next_frame`.

## Events: C++ fires, scripts listen

```cpp
inline constexpr Rhp::lua_event<"player.died", game::entity_id, std::string_view> player_died{};

player_died.fire(id, "lava"); // no-op with RHP_ENABLE=OFF, one atomic load when nobody listens
```

```lua
rhp.on("player.died", function(id, cause) print(id, cause) end)   -- removed with its module
```

Delivery is fire-and-forget (no return values; use patch points to change behavior). It is synchronous when fired on the thread that owns the subscribed sandbox, queued to the next `pump()` otherwise. String views and C strings are copied for queued delivery; application-defined argument types must also own anything the queued copy needs. Each handler runs as its own request and may `rhp.wait`. Arguments must be `Rhp::convertible` or a handle type that some installed lib declares.

## Custom types: `Rhp::convert<T>`

Built-in conversions cover the usual scalars, strings, containers and `Rhp::value`. For your own type specialize one struct; this is the single customization point for marshaling:

```cpp
struct vec2 {
    double x, y;
};

template <>
struct Rhp::convert<vec2> {
    static constexpr std::string_view lua_type = "number[]";

    static Rhp::value to_value(const vec2& v) {
        return Rhp::value{Rhp::value::array{Rhp::value{v.x}, Rhp::value{v.y}}};
    }

    static Rhp::result<vec2> from_value(const Rhp::value& v) {
        const auto* a = v.get_if<Rhp::value::array>();
        if (a == nullptr || a->size() != 2) {
            return Rhp::fail(Rhp::errc::kTypeMismatch, "expected a two-element array", "vec2");
        }
        auto x = Rhp::from_value<double>((*a)[0]);
        auto y = Rhp::from_value<double>((*a)[1]);
        if (!x || !y) {
            return std::unexpected{!x ? x.error() : y.error()};
        }
        return vec2{*x, *y};
    }
};
```

With `<rhp/rhp.hpp>` included, this maps `vec2` to a Lua array `{x, y}`. The optional `lua_type` improves generated LuaLS annotations. A specialization can instead supply `push(stack&, const T&)` / `pull(stack&, int)` for direct Lua access; `to_value` / `from_value` remain necessary for types sent through the client wire API. Opaque handle types are declared with `handle<>`, not exposed as raw pointers.

## Editor support: LuaLS stubs

```cpp
std::string text = box.stubs();                                    // the rhp API + every installed lib, for the sandbox's role
Rhp::script::stubs::write<game_lib>(std::cout, Rhp::role::kPatch); // from a lib type alone, no Lua needed
```

Remotely: `client.describe()`, or `rhp-cli stubs -c host:port -i dev.rhpid -o rhp_api.lua`. The output is filtered by the caller's role, so an observe key does not see `rhp.patch`.

## Compiling it out

With `-DRHP_ENABLE=OFF` host/client operations that return results report `kDisabled` and their pumps are inert, patch points become direct calls, `lua_event::fire` is a no-op and Lua is not even fetched. Use it for store or release builds that must not accept remote code.
