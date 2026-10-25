# Exposing C++ to Lua

Bindings describe the application capabilities available to scripts. Names and tag combinations are checked on the declaration line; argument/result conversions and the complete handle tree are checked by `install<Lib>()`. The examples below assume the referenced C++ functions and variables are already declared.

## `Rhp::lib`: functions, variables, handles

```cpp
using game_lib = Rhp::lib<"game">                                                                      // Lua sees the global `game`
    ::fn<"spawn", &game::spawn, Rhp::undo<&game::despawn>>                                             // reversible, needs patch role
    ::fn<"find", &game::find>                                                                          // pure, observe role
    ::fn<"explode", &game::explode, Rhp::irreversible>                                                 // allowed, but counted in revert reports
    ::fn<"wipe", &game::wipe, Rhp::requires_role<Rhp::role::kAdmin>>                                  // admin only
    ::var<"gravity", &game::g_gravity>                                                                // read: observe, write: patch (journaled)
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

## Methods and properties on handles

A handle can carry its own functions and read-only values. A method or property belongs to the handle type of its first parameter:

```cpp
using game_lib = Rhp::lib<"game">
    ::handle<"entity", game::entity_id, &game::is_alive>
    ::fn<"spawn", &game::spawn, Rhp::undo<&game::despawn>>
    ::method<"move", &game::move, Rhp::undo<&game::move_back>> // e:move(dx, dy); move(entity_id, float, float)
    ::method<"heal", &game::heal>                              // may return Rhp::async<T> like any binding
    ::property<"hp", &game::health_of>                         // e.hp; health_of(entity_id) -> int
    ::property<"owner", &game::owner_of, Rhp::requires_role<Rhp::role::kAdmin>>;
```

```lua
local e = game.spawn(0, 0)
e:move(3, 4)
print(e.hp)
```

| Entry | Meaning |
|---|---|
| `method<"name", &f, tags...>` | `h:name(args...)` calls `f(h, args...)`. Takes the `fn` tags (`undo`, `irreversible`, `requires_role`) and may be asynchronous. Errors are labelled `entity:name`; a missing or wrong handle is reported as `(self)` |
| `property<"name", &f [, requires_role<R>]>` | `h.name` reads `f(h)`. One parameter, a result, nothing to undo, no waiting |

- The handle must be declared in the same lib tree (a lib that only adds members to a handle declared elsewhere re-declares `::handle` with the same name, type and validity check). A stale handle fails every member with `kStaleHandle`.
- Members are read-only from Lua: `e.hp = 5` raises `kInvalidArgument`. An unknown member reads as `nil` (also on handle types without members). One property makes every lookup on that handle a C call (the methods-only `__index` is a plain table): see [benchmarks](../benchmarks.md).
- A name is used once per handle across the lib tree (compile time) and across libs installed into one sandbox (`install` fails with `kAlreadyLoaded` and adds no member; handle types it declared stay defined).
- Properties return exactly one value: no tuples, no `Rhp::async`, nothing to undo (compile errors otherwise). A handle type with several names in different libs is pushed (by events, by other libs) under the first name a sandbox saw.
- Handles delivered by events or returned by any lib carry the same members. Stubs list them under the handle's `---@class`.

## Asynchronous bindings: `Rhp::async<T>`

A binding that returns `Rhp::async<T>` lets work finish later, on any thread, while the script that called it waits without blocking the game:

```cpp
Rhp::async<std::string> fetch_profile(std::string player) {
    auto [later, done] = Rhp::make_async<std::string>();
    std::thread{[done, player] {
        if (!done.complete(download_profile(player))) { // or complete(Rhp::fail(errc::kNotFound, "no such player"))
            // false: nobody receives it any more; anything the work made is yours to clean up
        }
    }}.detach();
    return std::move(later); // a structured binding is not moved implicitly
}

using net_lib = Rhp::lib<"net">::fn<"profile", &fetch_profile>;
```

```lua
local profile = net.profile("ada") -- this request waits; pump() keeps running everything else
print(profile)
```

- `Rhp::make_async<T>()` returns the reading side (`Rhp::async<T>`, given to RHP) and the completing side (`Rhp::promise<T>`, copyable, any thread). The first `complete(value)` or `complete(error)` wins; later ones return `false` (it is `[[nodiscard]]`: `false` also means nobody will receive the result). `Rhp::async<T>::completed(result)` returns an operation that is already over (a cache hit, a bad argument): the script doesn't suspend. Dropping every promise copy without completing gives the script `kRuntime`. A moved-from promise does nothing.
- The result reaches the script at the next `pump()` after `complete()`. Errors are raised at the call site, so `pcall(net.profile, "ada")` catches them. `T` may be `void` or a tuple (several Lua values).
- Only a script's own thread can wait: from a patch handler, `on_save` / `on_restore` / `on_unload`, a coroutine the script created or a `table.sort` comparator the call fails with `kInvalidArgument` before your function runs (even when it would have been a `completed()` cache hit). Timers, frame callbacks, event handlers and tasks can wait.
- `undo<G>` is recorded when the result arrives (with the result, or with copies of the arguments). If the script is gone by then (cancelled, its module unloaded, `limits.async_ms` ran out), `promise::stop_requested()` turns true and, when a success still arrives, RHP takes it back with `G` at the next `pump()` (`stats().async_compensated`; a binding without an undo counts in `async_dropped`: its effect stays). `G` may then run after the module's other effects were undone, so it must tolerate stale state. A host keeps the calls of an identity whose sandbox closed (disconnect) and still takes their late successes back; a sandbox you destroy yourself gives up on them unless you keep `box.release_async()` and pump it: then `complete()` returns `false` and the producer cleans up.
- A `const std::string&` parameter refers to RHP's copy of the argument, which lives only while your function runs: capture by value (`[path]`) in work that finishes later.
- Waiting costs no instruction budget or wall time. `limits.async_ms` (script clock; 0 = no limit) bounds a wait with `kTimeout`.
- Parameters and results must own their data: `std::string_view` / `const char*` parameters, a `std::string_view` result, `async<async<T>>`, `async<Rhp::result<T>>` and `Rhp::result<async<T>>` don't compile.

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
- A call selects the newest layer owned by the calling thread; layers installed by other threads are skipped and counted by `off_thread_misses()` (`depth()` and `patched()` tell how many overrides are installed). Keep installation, Lua use and teardown on the same application thread. The point/event registries and variable-layer metadata are process-wide, so hosts are not isolated from shared application targets.
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

Delivery is fire-and-forget (no return values; use patch points to change behavior). It is synchronous when fired on the thread that owns the subscribed sandbox, queued to the next `pump()` otherwise. String views and C strings are copied for queued delivery; application-defined argument types must also own anything the queued copy needs. Each handler runs as its own request and may `rhp.wait`. Arguments must be `Rhp::convertible` or a handle type that some installed lib declares (a handle type no lib in a receiving sandbox declares arrives as its `convert` form, else nil; remote clients always get the `convert` form).

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
