# RHP — Remote Hot Patch · Architecture

> **Language:** C++23 · **Build:** CMake ≥ 3.28, Ninja Multi-Config, CPM.cmake · **License:** Apache-2.0
> **Targets:** Windows 10 1809+ · Linux (glibc 2.31+) · macOS 13.3+ · iOS 16.3+ · Android API 26+ — x86_64 + arm64
> **Compilers:** MSVC (VS 2026) · clang-cl · Clang 17+ · AppleClang · Android NDK Clang
> **Root namespace:** `Rhp::` · **Include root:** `<rhp/...>`
> **Current usage:** [user guide](guide/README.md) · **Open issues / verification:** [Status and TODO](TODO.md). The current implementation includes Stages 0–6. The historical decision logs below retain the decisions made at each stage; current Stage 6 choices are recorded in [networking decisions](decisions/stage6-networking.md).
> **Progress model:** work advances in **stages** (Stage 0, Stage 1, …). Nothing in code, files, tags, or APIs is ever named `v1`/`v2`/`V*`. The only numbers on the wire are a plain `protocol_revision` integer and per-module `revision` counters.

---

## 0. What RHP is

**One sentence:** *RHP is a portable, compile-time-configured C++23 static library that lets a running program accept authenticated, signed Lua scripts over pluggable transports, run them in a sandbox against a C++-declared API surface, stream results back, and undo their recorded application effects.*

| Requirement | How RHP meets it |
|---|---|
| Plug-and-play, expandable from outside | every axis is a **policy** checked by a **concept**; users add types/specializations, never edit RHP |
| Heavy `<>::` chaining | configuration and bindings are type-level DSLs: `Rhp::config<>::transport<..>::auth<..>`, `Rhp::lib<"game">::fn<..>::var<..>` |
| C++ is the executor, Lua is glue | Lua only reaches what C++ exposed via `Rhp::lib<>` and `Rhp::patch_point<>` |
| Loaded / unload / revert / reload | managed **modules** + an **undo ledger** + per-module revision history + global checkpoints |
| Portable to 5 OSes | no OS headers in public API; OS code only in `Src/rhp/platform/detail/*` and backend `.cpp`s |
| Network + error correction handled by RHP | framing, CRC32C, seq/ack, idempotency, heartbeat, reconnect, resume |
| Easy to use | `Rhp::config<>` supplies implemented defaults; applications choose execution budgets and check setup results |

**Use cases (decided):** game hot patching / modding · live tuning of dev builds · QA / test automation · server admin / ops · reverse-engineering / research tooling.

---

## 1. Big picture

```mermaid
flowchart LR
    subgraph DEV["Developer / QA / ops machine"]
        CLI["rhp-cli REPL"]
        TOOL["your C++ tool<br/>Rhp::client · Rhp::fleet"]
        CURL["curl / scripts<br/>(HTTP REST gateway)"]
    end

    subgraph NET["Transports (policies)"]
        T(("TCP · WebSocket · UDP-reliable<br/>Local IPC · Loopback · TLS decorators"))
        MD(["mDNS discovery<br/>_rhp._tcp · _rhp._udp"])
    end

    subgraph APP["Target process (game, server, mobile app)"]
        direction TB
        H["Rhp::host&lt;Cfg&gt;"]
        HG["optional HTTP/1.1 frontend"]
        SCHED["coroutine scheduler<br/>(time-sliced by pump)"]
        SB["Lua 5.5 sandbox<br/>one lua_State per key identity"]
        API["C++ surface<br/>Rhp::lib · patch_point · blob sinks"]
        CODE["user's real C++ code"]
        LED[("undo ledger<br/>+ revision history")]
        H --> SCHED --> SB --> API --> CODE
        API -. records inverse .-> LED
    end

    CLI & TOOL <--> T <--> H
    CURL <--> HG <--> H
    H -. advertises .-> MD -. found by .-> TOOL
```

**Key principle:** a script never "gets the process". It gets a capability table whose contents depend on its caller's **role**.

---

## 2. Layered architecture

Each layer may only depend on layers below it. Maintained through each module's CMake target dependencies; declaration order alone does not enforce this graph.

```mermaid
flowchart TB
    subgraph L5["Layer 5 — Front-end"]
        HOST["Rhp::host"]:::fe
        CLIENT["Rhp::client"]:::fe
        FLEET["Rhp::fleet"]:::fe
    end
    subgraph L4["Layer 4 — Session"]
        SESS["Rhp::session<br/>handshake · roles · seq/ack · resume · heartbeat · reconnect"]
    end
    subgraph L3["Layer 3 — Backends (policies)"]
        NETL["Rhp::net<br/>transports + discovery"]
        SEC["Rhp::security<br/>psk · signing · roles · tls"]
        EXEC["Rhp::exec<br/>executors + io thread"]
        SCRIPT["Rhp::script<br/>engine · sandbox · lib DSL · patch points · ledger · scheduler · stubs"]
    end
    subgraph L2["Layer 2 — Wire & Platform"]
        WIRE["Rhp::wire<br/>frame · envelope · msgpack codec"]
        PLAT["Rhp::platform<br/>OS traits · endian · time"]
    end
    subgraph L1["Layer 1 — Core"]
        CORE["Rhp::core<br/>error · result · value · convert · ids · log · limits · concepts"]
    end
    subgraph L0["Layer 0 — Utils (zero deps)"]
        UT["Rhp::utils<br/>fixed_string · type_list · scope_guard · spsc_ring · crc32c · units"]
    end
    L5 --> L4 --> L3 --> L2 --> L1 --> L0
    classDef fe fill:#2b6cb0,color:#fff,stroke:#1a365d
```

| Layer | Namespace | May know | Must not know |
|---|---|---|---|
| 0 | `Rhp::utils` | standard library | RHP, OS, Lua, sockets |
| 1 | `Rhp::core` | utils | Lua, sockets, threads |
| 2 | `Rhp::wire`, `Rhp::platform` | core | Lua, sessions |
| 3 | `Rhp::net`, `Rhp::security`, `Rhp::exec`, `Rhp::script` | layers 0–2 | each other |
| 4 | `Rhp::session` | backends **through concepts only** | concrete backend types |
| 5 | `Rhp::host`, `Rhp::client`, `Rhp::fleet` | everything, via `Rhp::config<>` | — |

Naming: everything is **snake_case** (std-like) under the `Rhp::` root — `Rhp::host`, `Rhp::script::patch_point`, `Rhp::errc::kBudgetExceeded`.

---

## 3. Extension model ("Render-API" style)

A stable front-end over swappable backends. Every backend slot is a concept; users plug in their own types. Extensions ship as **separate CMake targets** (compile-time only — no runtime-loaded plugin DLLs).

```mermaid
classDiagram
    direction LR
    class config {
        <<type-level builder>>
        transport~T~
        tls~S~
        codec~C~
        auth~A~
        signer~G~
        engine~E~
        executor~X~
        io~I~
        discovery~D~
        limits~L~
        logger~O~
        errors~R~
        clock~K~
    }
    class Transport {
        <<concept>>
        listen()
        dial()
        send()
        poll()
        close()
    }
    class Authenticator {
        <<concept>>
        challenge()
        respond()
        verify()
        role_of()
    }
    class Signer {
        <<concept>>
        sign()
        verify()
    }
    class ScriptEngine {
        <<concept>>
        compile()
        resume()
        call()
        reset()
    }
    class Executor {
        <<concept>>
        post()
        drain()
    }
    class Discovery {
        <<concept>>
        advertise()
        browse()
    }
    config ..> Transport
    config ..> Authenticator
    config ..> Signer
    config ..> ScriptEngine
    config ..> Executor
    config ..> Discovery
    Transport <|.. tcp
    Transport <|.. websocket
    Transport <|.. udp_reliable
    Transport <|.. local_ipc
    Transport <|.. loopback
    host --> http_listener : optional frontend
    Transport <|.. your_transport
    Authenticator <|.. psk_keyring
    Signer <|.. ed25519
    ScriptEngine <|.. puc_lua
    Executor <|.. pumped
    Executor <|.. threaded
    Executor <|.. inline_exec
    Discovery <|.. mdns
    Discovery <|.. no_discovery
```

### 3.1 Customization points

| Extension point | Kind | User does | Example |
|---|---|---|---|
| Transport | concept policy | satisfy `Rhp::net::transport` | Steam P2P, USB serial, in-house relay |
| TLS backend | concept policy | satisfy `Rhp::security::tls::backend` (a sans-IO `tls::engine` per connection) | platform TLS |
| Codec | concept policy | satisfy `Rhp::wire::codec` | debug JSON codec |
| Authenticator | concept policy | satisfy `Rhp::security::authenticator` | company SSO token |
| Script signer | concept policy | satisfy `Rhp::security::signer` | HSM-backed signing |
| Executor | marker policy | `Rhp::exec::pumped` only today | alternate scheduling is not wired into the engine |
| I/O threading | concept policy | satisfy `Rhp::exec::io_runner` start/stop contract | owned I/O thread or caller-polled `zero_threads` |
| Discovery | concept policy | `config<>::discovery<D>`, `net::discovery` | `mdns`, explicit `mdns_wire`, `no_discovery`; advertisement opt-in |
| Logger | concept policy | satisfy `Rhp::core::logger` | spdlog, logcat, os_log |
| Error mode | policy | `Rhp::errors::expected` / `Rhp::errors::throwing` | exceptions in tools, expected in engine |
| Memory | runtime injection | `sandbox_options::memory` for Lua; explicit byte-buffer resource | not universal engine allocation injection |
| Type marshaling | trait specialization | specialize `Rhp::convert<T>` | `vec3`, `entity`, `color` |
| Bindings | type-level DSL | `Rhp::lib<"name">::fn<...>` | expose functions + handles |
| Hot-patch sites | object | `Rhp::patch_point<"id", &default_fn>` | overridable behavior |
| Native hooking | planned integration | no shipped `hook_backend` concept/slot | application-supplied effects can use the ledger |
| Blob sinks | runtime registration | `host.on_blob("name", fn)` | receive textures, configs |
| Events | callbacks | `host.on<Rhp::event::X>(fn)` | audit, UI notification |

---

## 4. The type-level DSL

### 4.1 Configuration chain

```cpp
#include <rhp/rhp.hpp>
using namespace Rhp::literals;                                // _KiB, _MiB, _GiB size literals

using my_cfg = Rhp::config<>
    ::transport<Rhp::net::tcp>
    ::tls      <Rhp::security::tls::auto_backend>             // the system's OpenSSL where found, else Mbed TLS
    ::codec    <Rhp::wire::msgpack>
    ::auth     <Rhp::security::psk_keyring>                   // keys → identities → roles
    ::signer   <Rhp::security::ed25519>                       // scripts must be signed
    ::executor <Rhp::exec::pumped>                            // Lua runs on the thread that calls pump()
    ::io       <Rhp::exec::owned_io_thread>                   // RHP owns one network thread
    ::errors   <Rhp::errors::expected>                        // or Rhp::errors::throwing
    ::clock    <Rhp::exec::steady_clock>                      // injectable (game time, deterministic tests)
    ::logger   <Rhp::core::stderr_logger>
    ::limits   <Rhp::limits{}>;                               // everything unlimited, scripts run to completion
```

`Rhp::config<>` with no links equals exactly this. TLS activates automatically for non-loopback network endpoints. `engine<>` and `discovery<>` are not shipped slots; see AA2–AA5 and the guide's [configuration table](guide/configuration.md#rhpconfig). There is **no default port** — every endpoint names one.

The implementation uses `config_detail::setting<slot, T>` to identify each policy, `rebind_t` to replace a prior setting, and `get_or_t` to select defaults. Host/client facades turn the resulting types into function pointers and callbacks for engines compiled once. See [`config.hpp`](../Src/rhp/config/config.hpp).

Each slot is concept-constrained **where you write it**. A bad transport fails on the `::transport<X>` line, not deep inside `host.hpp`.

> In your own templates (dependent context) write `Cfg::template transport<X>`. In normal code no `template` keyword is needed.

### 4.2 Binding chain

```cpp
using game_lib = Rhp::lib<"game">
    ::fn <"spawn",   &game::spawn,   Rhp::undo<&game::despawn>>    // reversible; needs role::kPatch
    ::fn <"find",    &game::find>                                   // pure → role::kObserve
    ::fn <"explode", &game::explode, Rhp::irreversible>             // allowed, reported by revert
    ::fn <"wipe",    &game::wipe,    Rhp::requires_role<Rhp::role::kAdmin>>
    ::var<"gravity", &game::g_gravity>                              // read: observe, write: patch (journaled)
    ::ro <"tick",    &game::g_tick>
    ::handle<"entity", game::entity_id, &game::is_alive>            // opaque handle type + validity check
    ::sub<Rhp::lib<"debug">
        ::fn<"dump", &game::dump_state>>;
```

```lua
local e = game.spawn("crate", 10, 0, 5)   -- returns an opaque `entity` handle
game.gravity = -4.9                         -- old value journaled
print(game.tick, game.debug.dump())
```

Compile-time guarantees: names are `Rhp::utils::fixed_string` NTTPs and **duplicates don't compile**; every parameter/return type satisfies `Rhp::convertible`; `Rhp::undo<F>` must be invocable with the original's return value.

**Binding depth (decided):** free functions, variables, and **opaque handles** (typed IDs with a validity check). No full class/inheritance binding — keeps the binder small (~1 kLOC) and every registration ledger-tracked.

### 4.3 Patch points

```cpp
float default_damage(float base, int target);

inline constexpr Rhp::patch_point<"combat.damage", &default_damage> damage{};

float d = damage(base, target);   // RHP_ENABLE=ON : one atomic load + predictable branch
                                  // RHP_ENABLE=OFF: compiles to a direct call to default_damage
```

The default is a template argument (a function pointer or a captureless lambda) and the signature is deduced from it. That keeps all per-point state in the type: it is constant-initialized (safe to call during static initialization) and registers itself in the process-wide id table before `main`.

```lua
rhp.patch("combat.damage", function(original, base, target)
    return original(base, target) * 2.0
end)
```

Patches **stack** per point, so multiple modules can patch the same point and be reverted in any order. Native machine-code hooking and a formal `hook_backend` policy are not shipped; an application can record its own `effect` objects in a ledger.

### 4.4 C++ → Lua events

C++ can fire typed events that scripts subscribe to:

```cpp
inline constexpr Rhp::lua_event<"player.died", game::entity_id, std::string_view> player_died{};

player_died.fire(id, "lava");          // RHP_ENABLE=OFF → no-op
```

```lua
rhp.on("player.died", function(id, cause) print(id, cause) end)   -- subscription is ledger-tracked
```

Like patch points, `lua_event`s live in a **process-wide registry** (any host may deliver them to its scripts). Delivery is synchronous in sandboxes owned by the firing thread and queued to the next `pump()` of every other subscribed sandbox (arguments copied). Each handler runs as its own script request, so it may `rhp.wait`. A handle-type argument arrives as the handle userdata of whichever installed lib declares that type.

### 4.5 Opaque handles

`::handle<"entity", game::entity_id, &game::is_alive>` makes `entity` a distinct userdata type in Lua. Using a handle whose validity check fails raises a Lua error (`kStaleHandle`) — never a silent `nil`.

### 4.6 Custom types

```cpp
template <> struct Rhp::convert<vec3> {
    static Rhp::value to_value(const vec3& v);                              // wire + Lua (through Rhp::value)
    static Rhp::result<vec3> from_value(const Rhp::value& v);
    static void push(Rhp::script::stack& s, const vec3& v);                 // optional Lua fast path
    static Rhp::result<vec3> pull(Rhp::script::stack& s, int index);        // optional Lua fast path
};
```

`to_value` / `from_value` alone are enough for bindings; `push` / `pull` only skip the `Rhp::value` round trip.

No reflection-based automation; `convert<T>` is always written by hand (decided).

### 4.7 Editor stubs (LuaLS)

Every `Rhp::lib<>` can emit **LuaLS annotations** so script authors get autocomplete and type checks:

```cpp
Rhp::script::stubs::write<game_lib>(std::cout, Rhp::role::kPatch);   // compile-time walk of the lib type
std::string all = box.stubs();             // rhp API + every installed lib, for the sandbox's role
```

```lua
---@meta
---@class game
---@field gravity number
game = {}

---@param kind string
---@param x number
---@param y number
---@param z number
---@return entity
function game.spawn(kind, x, y, z) end
```

Stubs are filtered by role: functions the role can't call are left out and variables it can't write are marked `read-only`. Parameters are named `arg1..argN` (C++ has no parameter names without reflection); a `Rhp::convert<T>` names its Lua type with `static constexpr std::string_view lua_type`. `rhp-cli stubs > rhp_api.lua` fetches them from a running host (`op::describe`).

---

## 5. Scripts: lifecycle, scheduling, revert

### 5.1 Operations

| Op | Meaning | Min role |
|---|---|---|
| `exec(src)` | run once; effects **kept**, owned by the identity's **scratch module** (`revert(scratch)` undoes all REPL effects) | observe¹ |
| `load(name, src)` | compile, run top level, `on_load()`; loading an existing name = transactional reload | patch |
| `call(mod, fn, args...)` | call an exported module function | observe¹ |
| `reload(mod, src)` | compile new → `on_save()` old → revert old → swap → `on_restore(state)`; on failure old stays untouched | patch |
| `rollback(mod, n)` | swap back to a stored earlier **revision** (last N kept, configurable, default 8) | patch |
| `pin(mod)` / `unpin(mod)` | hand a module to the host so it survives disconnect (§5.7) | admin |
| `checkpoint(tag)` / `revert_to(tag)` | global ledger marks | patch |
| `revert(mod)` | undo every effect of `mod`; module stays loaded, inert | patch |
| `unload(mod)` | `on_unload()` → revert → drop `_ENV` → forget | patch |
| `revert_all()` | panic button: every module of every identity unloaded | admin |
| `cancel(req)` | stop a running script/coroutine | same identity or admin |
| `list` / `status` / `describe` | introspection, stubs | observe |
| `blob(sink, bytes)` | push a file to a host-registered sink (chunked) | admin (per-sink overridable) |

¹ observe sessions can run code, but any binding that mutates host state fails with `errc::kForbidden`.

### 5.2 Module state machine

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Rejected: auth / role / signature / size
    Received --> Compiling: verified
    Compiling --> Faulted: syntax error
    Compiling --> Running: text chunk OK
    Running --> Suspended: slice used up / rhp.wait()
    Suspended --> Running: next pump()
    Running --> Active: top level done + on_load() OK
    Running --> Faulted: runtime error
    Active --> Active: call() / rollback(n)
    Active --> Reloading: reload(src)
    Reloading --> Active: new revision OK or FAILED (old untouched)
    Active --> Reverted: revert()
    Reverted --> Active: reload()
    Active --> Unloaded: unload()
    Reverted --> Unloaded: unload()
    Faulted --> Unloaded: unload()
    Unloaded --> [*]
    Rejected --> [*]
```

**Fault policy (decided):** on runtime error the module's effects are auto-reverted and it stays in `Faulted` for inspection (`status` shows the traceback) until unloaded or reloaded.

### 5.3 Scheduler, limits, cancel

**Decided:** totals are unlimited and scripts **run to completion** by default (`slice_us = 0`). Every script still runs as a coroutine, so `rhp.wait(frames)`, `rhp.sleep(ms)`, `rhp.next_frame()` and `rhp.timer(ms, fn)` (ledger-tracked) let scripts spread work across frames **when they choose to**.

```mermaid
flowchart LR
    P["host.pump()"] --> Q{"ready coroutines?"}
    Q -- no --> R["return"]
    Q -- yes --> RUN["resume next coroutine"]
    RUN --> H{"count hook (every 1000 instr):<br/>cancel flag set? · optional slice/limit hit?"}
    H -- "cancel" --> C["raise kCancelled (sticky)<br/>auto-revert per fault policy"]
    H -- "slice hit (opt-in)" --> Y["lua_yield → continues next pump"]
    H -- no --> RUN
    RUN --> D["finished · rhp.wait() · error"]
    D --> Q
    C --> Q
    Y --> R
```

| Knob | Default | Effect |
|---|---|---|
| `limits.slice_us` | `0` = run to completion | opt-in time slicing per `pump()` |
| `limits.instructions` / `memory` / `wall_ms` | `0` = unlimited | opt-in totals, per config or per role; **sticky** when hit (re-raise every tick, allocator keeps refusing) so `pcall` can't swallow them |
| cancel flag | always on | set by the **I/O thread** (atomic) when `cancel` / `revert_all` / disconnect arrives; the count hook checks it, so a runaway loop can always be stopped **even while `pump()` is stuck inside it** |

> ⚠ Run-to-completion means an infinite loop holds the thread that called `pump()` (e.g. the game thread) until someone sends `cancel` or the client disconnects (§5.7). A count hook can't interrupt a long **C++** call, so bound functions must return.

### 5.4 Streaming output

| Lua | Wire | Client |
|---|---|---|
| `print(...)` | `op::output` frames **and** host logger | `on_output` callback / REPL prints live |
| `rhp.emit(value)` | `op::emit` frames tied to the request id | callback, or `co_await` an async stream |
| `return ...` | `op::result` | final `Rhp::result<T>` |

### 5.5 Undo ledger

```mermaid
flowchart LR
    S["Lua (module M, identity K)"] -->|"game.gravity = -4.9"| B["binding trampoline"]
    B --> RC{"1 · K has role::kPatch?"}
    RC -- no --> F["errc::kForbidden"]
    RC -- yes --> OLD["2 · read old value"]
    OLD --> LED[("3 · ledger record<br/>seq · module · identity · undo_fn · label")]
    LED --> CPP["4 · apply to C++"]
    R["revert(M)"] -->|"reverse seq order,<br/>records owned by M"| LED
```

| Effect | Recorded inverse |
|---|---|
| `::var` write | restore old value |
| `rhp.patch` | pop that handler from the point's stack |
| `::fn<..., Rhp::undo<F>>` | `F(result)` |
| `rhp.on(event)` / `rhp.timer` | unsubscribe / cancel |
| `hook_backend` install | uninstall |
| `::fn<..., Rhp::irreversible>` | none — reported as `irreversible_effects: N` |
| plain `::fn` | none (treated as pure) |

### 5.6 `require` between modules

Module names are dotted lowercase (`combat.low_grav`), same rule as patch ids. Chunk names are `@module_name`, so tracebacks read `@combat.low_grav:12`. Revisions are a per-module counter, with the content hash shown in `status`.

`require("name")` resolves only to **loaded modules of the same identity** (whatever their chunk returned), via a host-controlled loader — never the file system, for every role. It returns a read-only proxy that always reads the module's **current** exports, so dependents follow a reload or rollback. A require cycle fails with an error naming the chain. The host tracks the dependency graph; unloading a module that others require fails with `kHasDependents` unless `force` is passed (then dependents stay loaded and touching the unloaded module raises `kUnloaded`).

---

### 5.7 Session lifetime (disconnect = revert)

**Decided:** when a client's session ends, everything its identity did is **reverted immediately** and its `lua_State` is closed.

```mermaid
flowchart LR
    A["link drops"] --> B{"resumed with token<br/>before heartbeat death?<br/>(≈ 3 × 2 s)"}
    B -- yes --> C["same session continues<br/>nothing reverted"]
    B -- no --> D["session dead"]
    E["client close()"] --> D
    D --> F{"other live sessions<br/>for this identity?"}
    F -- yes --> G["keep state"]
    F -- no --> H["revert all modules + scratch · unload · lua_close"]
```

A Wi-Fi blip shorter than the heartbeat window does **not** revert; a real disconnect does.

*As built (Stage 5):* a lost link (or a heartbeat that died: a half-open link) detaches the session for `limits.resume_ms` (6 s); the side that dialed redials and resumes it, both ends resend what wasn't acknowledged, and nothing is reverted or run twice (AA7). Only a session that doesn't come back in time — or one closed on purpose — ends and reverts.

- **`pin(mod)`** (`kAdmin`): the host takes ownership of a module, so it survives its client's disconnect. Pinned modules belong to a host-owned identity, are reverted only by `unpin` + `revert`/`unload` or `revert_all`, and are listed with `pinned: true`. This is how `rhp-cli run patch.lua --pin` applies a lasting patch. *As built (Stage 4):* the identity's own sandbox stays alive while it has pinned modules; at its last disconnect the scratch module and every module the pinned ones don't `require` are reverted and unloaded (Y7).
- **HTTP gateway:** logical sessions survive physical socket close and expire after **5 minutes idle**. Expiry stops their pending requests and applies normal identity cleanup, preserving other live sessions and pinned modules.
- **Handshake flood guard:** clients are unlimited, but at most **64 unauthenticated** handshakes may be pending, each with a **5 s** timeout.

## 6. Using RHP

The [user guide](guide/README.md) contains the current API and runnable examples; the older design-time sketches have been removed from this section.

| Workflow | Guide |
|---|---|
| Add a CMake target, run a signed CLI session, embed a checked host/client | [Getting started](guide/getting-started.md) |
| Bind functions, variables and handles; supply inverses and custom conversions | [Exposing C++](guide/exposing-cpp.md) |
| Module exports, hooks, reload, checkpoints, timers, suspension | [Writing scripts](guide/writing-scripts.md) |
| Async consumption, callback/thread lifetimes, blobs and audit | [Host and client](guide/host-and-client.md) |
| TLS, reverse mode, resume, CLI and custom transports | [Connecting](guide/connecting.md) |
| Policies, execution budgets, build switches and disabled builds | [Configuration](guide/configuration.md) |

Local use is `Rhp::script::sandbox`, not a `host.local()` accessor. Script source arguments are strings/string views; there is no `Rhp::source::file` loader. Client credentials and signing keys are separate constructor inputs. Output callbacks are constructor options, not client setters.

In normal mode the client dials a listening host. In reverse mode the host dials a listening client. Both still need application/network progress; an application suspension is not bypassed by reversing the connection.

Stage 6 usage is documented in [networking and fleet](guide/networking.md): typed transports, explicit DNS-SD advertisement, collect-all fleet execution, and the authenticated HTTP listener attached to the existing host. Open defects and platform verification are listed in [Status and TODO](TODO.md).

---

## 7. Request path

```mermaid
sequenceDiagram
    autonumber
    participant C as Rhp::client
    participant IO1 as client io thread
    participant T as transport
    participant IO2 as host io thread
    participant Q as SPSC inbox
    participant P as host.pump()
    participant VM as lua_State (identity K)
    C->>IO1: exec(src) → envelope{req, idem, op, src, signature}
    IO1->>T: frame{seq, crc32c}
    T->>IO2: bytes
    IO2->>IO2: magic · revision · length · crc · MAC · seq dedupe
    IO2->>Q: push
    IO2-->>IO1: ack(seq)
    P->>Q: pop
    P->>P: role check · signature verify · audit event
    P->>VM: compile ("t") · resume (to completion or rhp.wait)
    VM-->>P: print → output frames · rhp.emit → emit frames
    VM-->>P: result | error
    P->>IO2: response (cached by idem key)
    IO2->>T: frames
    T->>IO1: bytes
    IO1-->>C: Rhp::result<T> / callbacks / co_await
```

---

## 8. Wire protocol

### 8.1 Frame

```text
 0               4                 5       6       8                16               24          28
 +---------------+-----------------+-------+-------+----------------+----------------+-----------+
 | magic "RHP\0" | protocol_rev u8 | flags |  op   |      seq       |      ack       |  length   |
 +---------------+-----------------+-------+-------+----------------+----------------+-----------+
 |                         payload (MessagePack, `length` bytes, ≤ 4 MiB)                         |
 +-----------------------------------------------------------------------------------------------+
 | crc32c 4B (omitted under TLS) | [ keyed-BLAKE2b MAC 32B on loopback/IPC ]                      |
 +-----------------------------------------------------------------------------------------------+
```

| Field | Purpose |
|---|---|
| `magic`, `protocol_rev` | reject garbage; `protocol_rev` is a plain integer agreed in `hello` |
| `flags` | `MAC`, `ACK_REQ`, `MORE` (fragment of a blob/large payload), `CRC_OMITTED` |
| `op` | 16 bits: `hello, challenge, response, welcome, resume` (handshake) · `exec, load, call, reload, rollback, unload, revert, revert_to, checkpoint, revert_all, cancel, list, status, describe, pin, unpin, blob` (requests) · `output, emit, result, error` (replies) · `ping, pong, ack, nack` (control) — see X5 |
| `seq` / `ack` | per-session monotonic + cumulative ack |
| `length` | ≤ `max_frame` (4 MiB), checked **before** allocating; blobs larger than that are fragmented (`MORE`) |
| `crc32c` | catches corruption TCP's checksum misses; dropped under TLS (AEAD covers it) — as built, flag `kCrcOmitted`, accepted only on encrypted links (AA6) |
| MAC | loopback/IPC integrity + replay protection (`seq` inside the MAC) |

The header is fixed binary; only the payload is MessagePack (maps 1:1 onto Lua values).

### 8.2 Reliability ("error correction")

```mermaid
flowchart TB
    A["frame"] --> B{"magic / revision OK?"}
    B -- no --> X1["drop · close after N strikes"]
    B -- yes --> C{"length ≤ max_frame?"}
    C -- no --> X2["close (DoS guard)"]
    C -- yes --> D{"crc32c OK?"}
    D -- no --> X3["nack(seq) → resend"]
    D -- yes --> E{"MAC OK? (if present)"}
    E -- no --> X4["error(auth) · close"]
    E -- yes --> F{"idem key seen?"}
    F -- yes --> G["replay cached response (no re-execution)"]
    F -- no --> H["dispatch → cache response"]
```

| Mechanism | Guards against |
|---|---|
| CRC32C | corruption on non-TLS links |
| seq/ack + resend window | loss across reconnects |
| resume token (from handshake) | re-attaching to in-flight requests after reconnect |
| idempotency key + bounded response cache | double execution on retry |
| ping/pong (2 s, dead after 3 misses) | half-open sockets, sleeping radios |
| capped exponential backoff + full jitter | reconnect storms |
| **UDP-reliable transport** | own fragmentation + selective ack + retransmit; optional FEC policy (the only place FEC applies) |

### 8.3 Session state machine

```mermaid
stateDiagram-v2
    [*] --> Disconnected
    Disconnected --> Connecting: dial / accept
    Connecting --> Handshaking: link up
    Connecting --> Backoff: fail
    Handshaking --> Ready: hello · challenge · response · role assigned
    Handshaking --> Closed: auth fail
    Ready --> Degraded: missed pongs
    Degraded --> Ready: pong
    Degraded --> Backoff: 3 missed
    Ready --> Backoff: link error
    Backoff --> Connecting: min(cap, base·2^n) · full jitter
    Backoff --> Closed: give up / close()
    Ready --> Closed: close()
    Closed --> [*]
    note right of Ready
        re-entry with resume token:
        resend unacked frames
    end note
```

---

## 9. Security

| Layer | Decision |
|---|---|
| Bind address | loopback / local IPC by default; non-loopback requires a keyring **and** TLS (or an explicit `insecure_lan` opt-in) |
| Authentication | `psk_keyring`: mutual challenge-response, keyed BLAKE2b (Monocypher); each key maps to an **identity** and a **role** |
| Roles | `observe` (read, pure calls) · `patch` (mutations, load/revert) · `admin` (revert_all, blobs, `io`, admin-tagged bindings) |
| Script signing | Ed25519 (Monocypher): host only runs code signed by a trusted developer key; `rhp-cli` signs automatically with the identity's private key |
| Channel | TLS 1.3 on networks: OpenSSL (desktop) / mbedTLS (iOS, Android) behind `tls::auto_backend`; keyed-BLAKE2b frame MAC on loopback/IPC. *As built (Stage 5):* the PSK handshake is bound to the TLS connection (RFC 9266 tls-exporter), so the host's certificate needs no PKI; `ca_pem` adds certificate checks (AA4) |
| Sandbox | allowed libs: `string`, `table`, `math`, `utf8`, `coroutine`, `os.time`/`os.clock`; **full standard library for `kAdmin`** — `io`, `os` (incl. `execute`, `getenv`, `remove`, `rename`), `package.loadlib`, `debug` (decided: an admin key is fully trusted; `package.loadlib` can't load unsigned native code on iOS anyway); no `debug`, `package`, `dofile`, binary chunks (`load` forced to `"t"`), `string.dump` |
| Limits | unlimited, run to completion by default; cancel always works; optional sticky totals / slicing per role |
| Connections | unlimited concurrent clients per host (decided) — every one must authenticate |
| Discovery leak | mDNS TXT advertises host name, platform, protocol_rev, app name + build id, installed lib names **only when the host opts in** (off by default). Never keys. `discovery<Rhp::net::no_discovery>` turns it off |
| Audit | `Rhp::event::script_executed {identity, role, op, module, hash, signer, time}` + optional file sink |
| Kill switches | compile-time `RHP_ENABLE=OFF` (host becomes a stub, patch points become direct calls) **and** runtime `host.set_enabled(false)` |

> **iOS/App Store:** remote code that changes app behavior is restricted by store policy. Target dev/QA/enterprise builds; compile out with `RHP_ENABLE=OFF` for store builds. Check current Apple guidelines before shipping.

---

## 10. Threading

```mermaid
flowchart LR
    subgraph IO["RHP-owned I/O thread (Asio)"]
        RX["recv · verify"] --> IN[["SPSC inbox"]]
        OUT[["SPSC outbox"]] --> TX["encode · send"]
        DISC["mDNS advertise / browse"]
    end
    subgraph USER["User thread — host.pump()"]
        PUMP["scheduler: resume ready coroutines"] --> VMS["lua_State per identity"]
        VMS --> RES["results · output · emit"]
    end
    IN --> PUMP
    RES --> OUT
```

| Decision | Choice |
|---|---|
| Who runs Lua | `exec::pumped`: the thread calling `pump()` |
| Who runs network I/O | `exec::owned_io_thread`: one `std::jthread` running Asio (alternative: `zero_threads` = user polls; external-context injection is not shipped) |
| Memory | standalone Lua allocations and explicit byte buffers support a `std::pmr::memory_resource*`; other C++ allocations use their usual allocators |
| Isolation | one `lua_State` per **key identity**, one `_ENV` per module; identities never share a state |
| Concurrency rule | each `lua_State` is used on one application thread; rings, cancel relays, queued events and pending client results carry cross-thread state |
| Hosts per process | many; **no globals** in hosts (decided) |
| Patch points / lua_events | one **process-wide registry**; any host may patch/deliver; stacking order = global ledger seq |
| Patch point hit off the pump thread | Lua states aren't thread-safe, so the call runs the **C++ default** and increments a per-point `off_thread_misses` counter (shown in `status`) |
| `lua_event` delivery | synchronous when fired on the owning pump thread, queued to the next `pump()` otherwise; fire-and-forget (no return values — use patch points to modify behavior) |
| Clock | `clock<>` policy, `steady_clock` default; inject game time or a manual clock for deterministic tests |

---

## 11. Repository layout

```text
RHP/
├── CMakeLists.txt
├── CMakePresets.json
├── .clang-format                  # 4 spaces, attached braces (rest: see F20)
├── README.md
├── LICENSE                        # Apache-2.0
├── NOTICE
├── cmake/
│   ├── CPM.cmake
│   ├── Dependencies.cmake         # every pin in one place
│   ├── RhpOptions.cmake
│   ├── RhpWarnings.cmake
│   ├── RhpSanitizers.cmake
│   └── RhpPlatform.cmake
├── Src/
│   ├── CMakeLists.txt
│   └── rhp/
│       ├── rhp.hpp                # umbrella
│       ├── CMakeLists.txt
│       ├── utils/      fixed_string · type_list · function_traits · scope_guard · spsc_ring
│       │               byte_buffer · crc32c(.cpp) · units · overloaded · detail/
│       ├── core/       error · result · errors_mode · value(.cpp) · convert · ids · log(.cpp) · limits
│       ├── platform/   os · random(.cpp)                                    (Stage 3) ← only OS #ifdefs
│       ├── wire/       ops · frame(.cpp) · codec · codec/msgpack(.cpp) · messages(.cpp)   (Stage 3)
│       ├── net/        endpoint · io_context(.cpp) · link · loopback/ · tcp/          (Stage 3)
│       │               discovery · local/ · websocket/ · udp_reliable/ · mdns/ · detail/http   (Stage 6)
│       ├── security/   authenticator · key(.cpp) · keyring(.cpp) · psk_keyring(.cpp)  (Stage 3)
│       │               signer · ed25519(.cpp) · signing_keys(.cpp) · identity_file(.cpp) · hash(.cpp)   (Stage 4)
│       │   tls/        tls · openssl(.cpp) · mbedtls(.cpp) · auto_backend — Rhp::security::tls  (Stage 5)
│       ├── exec/       executor (pumped, steady_clock) · io_runner (owned_io_thread, zero_threads)
│       ├── script/     stack · marshal · lib · patch_point · ledger · sandbox     (Stage 1)
│       │               lua_event · stubs · scheduler, revisions, require in sandbox (Stage 2)
│       │               hook_backend                                               (later)
│       ├── event/      events(.cpp) · hub — typed host events, subscriptions, JSON  (Stage 4)
│       ├── audit/      sinks(.cpp) — file_sink, ostream_sink                        (Stage 4)
│       │               puc_lua/(.cpp — lua.h never leaks) · detail/
│       ├── session/    session(.cpp): handshake · seq/ack/nack · MAC · heartbeat   (Stage 3)
│       │               resume · secure_link(.cpp): TLS over any link, channel_policy   (Stage 5)
│       ├── config/     config — the Rhp::config<> chain                              (Stage 3)
│       ├── host/       host · detail/engine — host.cpp (+ blobs, events, pin, reverse: Stage 4)
│       │               local_api                                                     (later)
│       └── client/     client · pending · detail/engine — client.cpp                 (Stage 3–4)
│                       fleet · async_stream                                          (later)
├── Tests/
│   ├── CMakeLists.txt
│   ├── unit/          mirrors Src/rhp/* — files named `<thing>_tests.cpp`
│   ├── support/       header-only test helpers (`rhp_test/…`)
│   ├── integration/   host_client (Stage 3) · stage4 (signing, audit, blobs, pin, reverse, async)
│   ├── tools/         rhp-cli in-process + as a process against headless_server
│   ├── compile_fail/  bad concepts, duplicate names — ctest WILL_FAIL
│   ├── fuzz/          frame · envelope · msgpack · sandbox_escape (Stage 5)
│   └── bench/         patch_point_call · frame_roundtrip · exec_latency · slice_overhead
├── Examples/
│   ├── hello_console/     exec · expose · patch points · load/revert/rollback, local + over TCP
│   ├── custom_transport/  writing your own Rhp::net::transport
│   └── headless_server/   standalone host: key files, audit log, blobs, reverse mode (Stage 4)
├── Tools/
│   ├── rhp-cli/           REPL (replxx, CLI11): connect · exec · load · revert · rollback · pin · stubs · watch · run · keygen · sign · blob
│   ├── android/           run_tests.py — the test executables on a device / emulator over adb (Stage 5)
│   └── ios/               simctl_run.sh — the ios-sim preset's test runner (Stage 5)
├── Scripts/               sample .lua used by examples/tests
└── Docs/
    ├── ARCHITECTURE.md
    └── decisions/         one file per decision, named by topic (`lua-runtime.md`, no numbers)
```

Rules:
1. Top level capitalized (`Src`, `Tests`, `Examples`, `Tools`, `Docs`); everything under `Src/rhp/` is **lowercase** because it's an include path and Linux/Android/iOS are case-sensitive.
2. Folder ↔ namespace: `Src/rhp/script/` ⇔ `Rhp::script`; `detail/` ⇔ `Rhp::script::detail`.
3. One `CMakeLists.txt` per module folder, files listed explicitly, no `GLOB_RECURSE`.
4. Third-party headers (`lua.h`, `asio.hpp`, OpenSSL, mbedTLS, Monocypher, msgpack) only in `.cpp` files.
5. `.hpp`/`.cpp`, `#pragma once`, 4-space indent, attached braces.
6. No `v1`/`v2`/`V*` in any identifier, file, folder, namespace, or tag.

---

### 11.1 Code style (decided)

| Rule | Choice | Example |
|---|---|---|
| Types, functions, variables, namespaces | `snake_case` | `module_manager`, `revert_all()` |
| Root namespace | `Rhp::` | `Rhp::script::lib` |
| Constants & enum values | `kPascal` | `Rhp::errc::kForbidden`, `Rhp::role::kAdmin`, `kDefaultRevisions` |
| Template parameters | short PascalCase | `template <net::transport T>`, `Cfg`, `Fn` |
| Data members | trailing underscore | `ledger_`, `sessions_` |
| Macros | `RHP_*` | `RHP_ENABLE` |
| Constraints | constrained parameters in the list, not trailing `requires` | `template <Rhp::convertible T>` |
| `template <...>` | always on its own line | |
| Indent / braces | 4 spaces, attached braces | `void f() {` |
| Column limit | none (`ColumnLimit: 0`) | |
| Pointers | `int* p`, `int& r` | |
| One-line functions | only empty or in-class inline | |
| Include order | std → third-party → rhp | |
| Strings | `std::string_view` in, `std::string` out, UTF-8 everywhere | |
| Files | `.hpp` / `.cpp`, `#pragma once`; pure templates header-only, `.cpp` only for dependency walls | |
| Log levels | `trace, debug, info, warn, error, critical` | |
| Naming taboo | no `v1`/`v2`/`V*` anywhere | |

```cpp
namespace Rhp::script {

template <net::transport T, Rhp::convertible R>
class request_handle {
public:
    [[nodiscard]] Rhp::result<R> wait() const;
    bool done() const noexcept { return done_; }

private:
    T* transport_ = nullptr;
    bool done_ = false;
};

inline constexpr std::size_t kDefaultRevisions = 8;

}
```

## 12. CMake

### 12.1 Targets

```mermaid
flowchart BT
    utils["rhp_utils"]
    core["rhp_core"] --> utils
    platform["rhp_platform"] --> core
    wire["rhp_wire"] --> core
    script["rhp_script"] --> core
    script -. PRIVATE .-> lua[["Lua 5.5 (as C++)"]]
    net["rhp_net"] --> platform
    net -. PRIVATE .-> asio[["Asio"]]
    sec["rhp_security"] --> wire
    sec -. PRIVATE .-> mono[["Monocypher"]]
    tlsmod["rhp_tls"] --> core
    tlsmod -. PRIVATE, optional .-> tls[["OpenSSL (system) / Mbed TLS 4.2"]]
    session --> tlsmod
    exec["rhp_exec"] --> core
    session["rhp_session"] --> net
    session --> sec
    session --> exec
    session --> wire
    config["rhp_config"] --> net
    config --> sec
    config --> exec
    config --> wire
    host["rhp_host"] --> config
    host --> session
    host --> script
    event["rhp_event"] --> core
    audit["rhp_audit"] --> event
    host --> event
    client["rhp_client"] --> config
    client --> session
    rhp["Rhp::rhp"] --> host
    rhp --> client
    rhp --> audit
    cli["rhp-cli (Tools)"] --> rhp
    cli -. PRIVATE .-> rx[["replxx · CLI11"]]
```

### 12.2 Options

| Option | Default | Effect |
|---|---|---|
| `RHP_ENABLE` | `ON` | `OFF` → inert host, direct-call patch points |
| `RHP_BUILD_TESTS` / `RHP_BUILD_EXAMPLES` / `RHP_BUILD_TOOLS` | `ON` when top-level | |
| `RHP_WITH_TLS` | `ON` | OpenSSL desktop / mbedTLS mobile |
| `RHP_TLS_OPENSSL` | `AUTO` | the system's OpenSSL ≥ 3.0: `AUTO` (if found, desktop only), `ON` (required), `OFF` |
| `RHP_TLS_MBEDTLS` | `ON` | build the Mbed TLS backend (fetched) |
| `RHP_FUZZ` | `OFF` | Tests/fuzz as libFuzzer executables (Clang) |
| Stage 6 networking | `RHP_ENABLE` / typed policies | choose WebSocket, reliable UDP or IPC with `transport<>`; `discovery<no_discovery>` disables discovery; HTTP listener and advertisement are runtime opt-ins |
| `RHP_SANITIZE` | empty | `address;undefined` or `thread` |
| `RHP_WARNINGS_AS_ERRORS` | `ON` | `/W4 /WX` · `-Wall -Wextra -Wpedantic -Werror` |

### 12.3 Presets (Ninja Multi-Config; opens directly in Visual Studio)

| Configure preset | Toolchain | Tests run |
|---|---|---|
| `windows-msvc` | MSVC (VS 2026), Windows 10 1809+ | ✅ |
| `windows-clang-cl` | clang-cl | ✅ |
| `windows-msvc-asan` | MSVC AddressSanitizer | ✅ |
| `linux-clang` / `linux-clang-asan` / `linux-clang-tsan` | Clang 17+, glibc 2.31+ | ✅ |
| `linux-clang-fuzz` | Clang, `RHP_FUZZ=ON`, ASan+UBSan, RelWithDebInfo | libFuzzer runs (Tests/fuzz/README.md) |
| `macos` | AppleClang, `arm64;x86_64`, macOS 13.3+ | workflow defined; unverified |
| `ios-sim` | Xcode + AppleClang, `CMAKE_SYSTEM_NAME=iOS`, iOS 16.3+, simulator | unverified; runner uses `xcrun simctl spawn` as crosscompiling emulator (`Tools/ios/simctl_run.sh`, CI) |
| `ios-device` | Xcode, arm64 | build only |
| `android-x64` | NDK Clang, API 26+ (`ANDROID_NDK_HOME`); built with NDK 29 | build verified; hosted emulator job unverified; adb runner available |
| `android-arm64` | NDK Clang; tested with NDK 29 | build only (with `-DRHP_BUILD_TESTS=ON` the same runner tests on a phone) |

```bash
cmake --preset windows-msvc
```

```bash
cmake --build --preset windows-msvc --config Debug
```

```bash
ctest --preset windows-msvc -C Debug
```

### 12.4 Consuming RHP (CPM / add_subdirectory)

```cmake
CPMAddPackage(NAME rhp GITHUB_REPOSITORY tonytranrp/RHP GIT_TAG <commit-sha>)
target_link_libraries(my_game PRIVATE Rhp::rhp)
```

---

## 13. Testing

```mermaid
flowchart TB
    U["unit (mirrors Src/rhp)"] --> I["integration<br/>loopback → TCP → TLS"]
    I --> F["fuzz: frame · envelope · msgpack · sandbox"]
    I --> CF["compile-fail: concepts, duplicate names"]
    I --> B["bench: patch point · roundtrip · slice overhead"]
```

Must-have cases: revert matrix (every effect kind × load/reload/rollback/revert/revert_to/unload × cross-module interleaving) · transactional reload · scheduler (cancel from the I/O thread stops an infinite loop inside `pump()`; opt-in `slice_us` yields on time) · sandbox escapes · roles (observe can't mutate) · signing (unsigned/wrong-key rejected) · reconnect+resume exactly-once · CRC corruption → nack → resend · blob fragmentation · boundary instantiations (`Rhp::config<>`, empty `Rhp::lib<"x">`, `void` returns, minimal user transport).

**CI:** `.github/workflows/ci.yml` defines the Stage 5 matrix. Its current macOS step name has a YAML syntax error, and prior jobs report an account billing/spending-limit block. No hosted platform verification should be inferred until the corresponding jobs pass; see [Status and TODO](TODO.md). Android device suites use the adb runner; the iOS simulator runner integrates with ctest.

---

## 14. Errors

```cpp
namespace Rhp {
enum class errc : std::uint16_t {
    kOk, kTransport, kProtocol, kProtocolRevisionMismatch, kAuth, kForbidden, kBadSignature, kIntegrity, kTimeout,
    kCompile, kRuntime, kBudgetExceeded, kMemoryExceeded, kStaleHandle,
    kNotFound, kAlreadyLoaded, kHasDependents, kRevertPartial, kIrreversible, kCancelled, kLimitExceeded, kDisabled
};
struct error { errc code; std::string message; std::string where; std::string traceback; };
template <class T> using result = std::expected<T, error>;
struct exception : std::exception { error err; /* what() → err.message */ };
}
```

- `Rhp::errors::expected` (default): APIs return `Rhp::result<T>`.
- `Rhp::errors::throwing`: same APIs return `T` and throw `Rhp::exception`. `Rhp::unwrap(r)` converts one call.
- Internally exceptions are allowed. Expected mode selects ordinary result-bearing operation errors; it does not make constructors, allocation failures or user code universally nonthrowing. Lua is compiled as C++, so `lua_error` unwinds with exceptions and RAII stays correct; binding trampolines turn C++ exceptions into Lua errors.
- RTTI allowed.

---

## 15. Dependencies

All PRIVATE; none of their headers appear in `Src/rhp/**/*.hpp`.

| Need | Pick | License |
|---|---|---|
| Script engine | PUC Lua 5.5.1 via CPM, built by us as C++ | MIT |
| Binding | own concept binder (`Rhp::lib<>`) | — |
| Async I/O | standalone Asio 1.38.2 (Stage 3) | BSL-1.0 |
| Payload | own MessagePack codec for `Rhp::value` (`Rhp::wire::msgpack`; msgpack-c dropped at Stage 3, W2) | — |
| Integrity | CRC32C (own software slicing-by-8; hardware dispatch not implemented) | — |
| Crypto | Monocypher 4.0.3, compiled as C++ (BLAKE2b handshake + frame MAC from Stage 3; its optional RFC 8032 Ed25519 for script signatures and BLAKE2b-256 audit hashes from Stage 4) | CC0 / BSD-2 |
| CLI | CLI11 2.7.2 (header-only) · replxx `release-0.0.4` (line editing; upstream quiet since 2021, built by our own target) — `rhp-cli` only | BSD-3 · BSD-3 |
| TLS | OpenSSL 4.0.x (desktop) · mbedTLS 4.2 (mobile, custom Asio stream adapter) — as built: the system's OpenSSL ≥ 3.0 and Mbed TLS 4.2.0, both behind one sans-IO engine (no Asio SSL streams) | Apache-2.0 |
| WebSocket | own RFC 6455 framing on Asio | — |
| HTTP gateway | own minimal HTTP/1.1 parser on Asio | — |
| mDNS / DNS-SD | behind `Rhp::net::discovery`: Windows DNS-SD API, Apple `dns_sd`, own multicast responder on Linux/native Android; app NSD bridges can supply a policy (see Stage 6 decisions) | — |
| Tests | Catch2 v3.16 | BSL-1.0 |
| Bench (planned; not fetched) | Google Benchmark | Apache-2.0 |
| Fetching | CPM.cmake 0.42.x | MIT |

Apache-2.0 for RHP is compatible with all of the above.

---

## 16. Stages

```mermaid
flowchart LR
    S0["Stage 0<br/>layout · CMake · presets<br/>utils · core"] --> S1["Stage 1 · first demo<br/>Lua 5.5 sandbox · lib DSL<br/>patch points · ledger · revert<br/>(local only)"]
    S1 --> S2["Stage 2<br/>scheduler · emit/print<br/>revisions · on_save/on_restore<br/>require · stubs"]
    S2 --> S3["Stage 3<br/>wire · loopback · TCP<br/>session · psk roles"]
    S3 --> S4["Stage 4<br/>client · rhp-cli · signing<br/>audit · blobs · reverse mode"]
    S4 --> S5["Stage 5<br/>TLS · reconnect/resume<br/>fuzzing · mobile presets"]
    S5 --> S6["Stage 6<br/>WebSocket · UDP-reliable<br/>HTTP gateway · mDNS · fleet"]
```

| Stage | Done when |
|---|---|
| 0 ✅ | `cmake --preset windows-msvc` + `ctest` green with utils/core tests — done: 54 tests green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan |
| 1 ✅ | `Examples/hello_console` runs a local Lua file calling exposed C++, patches a point, and reverts everything — done: 118 tests (56 script) green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan; the `RHP_ENABLE=OFF` build is green without Lua |
| 2 ✅ | an infinite-loop script never blocks a frame; reload keeps state via `on_save`/`on_restore`; LuaLS stubs generated — done: `Examples/frame_loop` pumps 120 frames next to a `while true do end` (2 ms slices, worst frame ≈ 2 ms), reloads a module keeping its state and writes `rhp_api.lua`; 239 tests green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan; the `RHP_ENABLE=OFF` build (99 tests) is green without Lua |
| 3 ✅ | exec over loopback and TCP with CRC, seq/ack, roles — done: `Examples/remote_exec` runs three keys (admin / patch / observe) against one host over loopback and TCP on 127.0.0.1, streams print back, cancels a `while true do end` from the network thread while the game thread is stuck in it, and reverts a client's effects when it disconnects; `Examples/custom_transport` plugs a user transport into `Rhp::config<>`; 324 tests green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan; the `RHP_ENABLE=OFF` build (137 tests) is green without Lua, Asio or Monocypher |
| 4 ✅ | full lifecycle from `rhp-cli`, signed scripts only, audit log written — done: `rhp-cli` (replxx + CLI11) runs keygen → host key files → a signed REPL session (multi-line Lua, load / reload / rollback / call / pin / unload, stubs, blob, watch) against `Examples/headless_server` as a separate process, which writes a JSON-lines audit log; unsigned scripts from patch/admin are refused (`kBadSignature`); reverse mode (`rhp-cli --listen`, `headless_server --reverse`), async client calls (then / get / future / `co_await`), blobs and `pin` work over loopback and TCP; 370 tests green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan; the `RHP_ENABLE=OFF` build (153 tests) is green without Lua, Asio or Monocypher |
| 5 ✅ | TLS on all 5 OS presets; kill-the-socket test resumes exactly-once — done: TLS 1.3 through OpenSSL (system) and Mbed TLS 4.2 behind `config<>::tls<>`, the PSK handshake bound to the TLS channel (a TLS-terminating relay fails it), resume after a lost link (200 calls through 20 socket cuts run exactly once, over TLS too, reverse mode too), libFuzzer targets for frame / envelope / msgpack / sandbox_escape (the sandbox fuzzer found and fixed a Lua stack overrun); 398 tests green on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan, Clang TSan; the `RHP_ENABLE=OFF` build (155 tests) is green without Lua, Asio, Monocypher or TLS; Android: `android-arm64` / `android-x64` build with NDK 29 and every suite passed on an arm64 phone (Android 16) through `Tools/android/run_tests.py`; libFuzzer ran ~13 million inputs across the four targets clean; macOS and the iOS simulator are covered by the CI workflow, which couldn't run yet (the account's Actions billing blocks jobs) |
| 6 ✅ | fleet finds hosts via mDNS and broadcasts a script — the separate-process CLI discovers two hosts and collects both signed results over TLS; transports, gateway, discovery, fleet and tools are implemented. The review follow-ups are finished (§32): HTTP answer proofs and channel binding, host-clock idle expiry, per-request audit peers, a compiled fleet engine on one shared reactor with `load`/`call` broadcasts, and the four earlier runtime defects. Exact checks and platform limits: [Status and TODO](TODO.md). |

---

## 17. Research basis (2026-10-08)

| Finding | Consequence |
|---|---|
| Lua 5.4.9 is the final 5.4 release; 5.5.1 current | Lua 5.5 only |
| sol2 inactive since Mar 2025, breaks on GCC 15 / Lua 5.5 | own binder (also needed for ledger tracking) |
| Binary chunks unverified, can crash the VM | `load` forced to `"t"`, `string.dump` removed |
| Lua 5.4+ count hooks may `lua_yield` | time-sliced scheduler makes "unlimited" safe for pumped hosts |
| Lua compiled as C++ unwinds with exceptions | RAII-safe trampolines |
| `_ENV` isolation leaks via shared metatables | separate `lua_State` per identity |
| Owner-keyed cleanup (GMod hooks, Neovim augroups, Roblox Maid) | ledger design |
| `std::execution` has no networking until C++29 | Asio behind our transport concept |
| iOS: no listening while suspended; local-network prompt | reverse mode, Info.plist keys |
| Asio TLS speaks only OpenSSL | mbedTLS needs our own stream adapter |
| Monocypher has no SHA-256/HMAC | BLAKE2b MAC; audit hash choice in F19 |
| TCP checksum misses ~1 in 10^8–10^9 packets | CRC32C when not under TLS |

Sources: lua.org/versions.html · github.com/ThePhD/sol2 · github.com/kunitoki/LuaBridge3 · luau.org/sandbox · think-async.com/Asio · open-std.org P4048R0 · github.com/msgpack/msgpack-c · monocypher.org · Apple TN3151/TN3179 · developer.android.com/ndk · github.com/catchorg/Catch2.

---

## 18. Decision log (round 1)

| # | Topic | Decision |
|---|---|---|
| 1 | Name | Remote Hot Patch |
| 2 | Use cases | game patching/modding · live tuning · QA automation · server ops · RE/research |
| 3 | Standard | C++23 |
| 4 | Form | static library |
| 5 | License | Apache-2.0 |
| 6–7 | Naming | snake_case everything, root namespace `Rhp::` |
| 8–9 | Platforms | Windows, Linux, macOS, iOS, Android · x86_64, arm64 |
| 10 | Compilers | MSVC (VS 2026), clang-cl, Clang 17+ (see F1 for Apple/NDK) |
| 11–12 | Exceptions / RTTI | internal only, never across API · RTTI allowed |
| 13–14 | Lua | PUC Lua 5.5, built by us as C++ via CPM |
| 15 | Isolation | `lua_State` per client identity, `_ENV` per module |
| 16–17 | Binding | own concept binder · functions + opaque handles |
| 18 | Stdlib | string, table, math, utf8, coroutine, os.time/clock, io (admin-gated) |
| 19 | Stubs | LuaLS annotations from `Rhp::lib` |
| 20 | require | host-controlled loader |
| 21 | Persistence | in-memory only |
| 22–24 | Output / async | print → both · `rhp.emit` streaming · coroutine scheduler |
| 25 | Limits | unlimited totals, time-sliced pump |
| 26–27 | Hooking | patch points only, user `hook_backend` · atomic pointer, direct call when disabled |
| 28–30 | Effects | exec keeps (scratch module) · irreversible allowed + reported · fault → auto-revert, stay Faulted |
| 31–33 | History | last N revisions · `on_save`/`on_restore` · global checkpoints |
| 34 | Local API | yes |
| 35 | Transports | TCP, local IPC, loopback, WebSocket, TLS, UDP-reliable, HTTP REST |
| 36–39 | Topology | both directions · many isolated clients · `Rhp::fleet` · mDNS |
| 40–43 | Wire | Asio · MessagePack · no compression · 4 MiB frames |
| 44 | Blobs | yes, host-registered sinks |
| 45–49 | Security | PSK + signed scripts · OpenSSL + mbedTLS · roles per key · audit · compile-time + runtime kill switch |
| 50–53 | Threads / memory | pumped · RHP-owned I/O thread · blocking + co_await + callbacks + future · `std::pmr` |
| 54–56 | Errors / log / format | expected + throwing · own logger concept · `std::format` |
| 57–58 | Reflection / modules | no · headers only |
| 59–62 | Build | CPM · consumed via CPM/add_subdirectory · CMake 3.28 · Ninja Multi-Config |
| 63–65 | Env | Visual Studio · Catch2 v3 · no CI yet |
| 66–69 | Style | custom clang-format · 4 spaces, attached braces · lowercase include tree · `.hpp`/`.cpp` |
| 70–75 | Extras | Markdown docs · rhp-cli · no C API · C++ clients only · examples: hello_console, custom_transport, headless_server · compile-time extensions only |
| 76 | First demo | local Lua calling C++ + revert (Stage 1) |
| 77 | Versioning | no `v1`/`v2`/`V*` anywhere; progress = stages |

---

## 19. Decision log (round 2)

| # | Decision |
|---|---|
| F1 | AppleClang + Android NDK Clang added |
| F2–F4 | `Rhp::` root, snake_case sub-namespaces, `<rhp/...>`, CMake `Rhp::rhp`, macros `RHP_*` |
| F5 | full `io` for `kAdmin` |
| F6 | disconnect → revert immediately (after heartbeat window, §5.7) |
| F7–F8 | all code signed (CLI signs transparently); `kObserve` may run unsigned |
| F9 | scripts run to completion; slicing opt-in; cancel via atomic flag |
| F10–F11 | revisions configurable (default 8) · scratch module per identity |
| F12 | unload with dependents refused unless `force` |
| F13 | fleet: parallel, collect all |
| F14–F15 | WebSocket for proxy traversal only · HTTP/1.1 own parser |
| F16–F17 | platform DNS-SD APIs · TXT: host, platform, protocol_rev, app + build id, lib names |
| F18–F19 | blobs: `kAdmin`, 256 MiB · audit hash BLAKE2b-256 |
| F20–F22 | no column limit · `int* p` · one-liners only empty/in-class · std → third-party → rhp · `template <>` own line · constrained params · `T`/`Cfg` · `x_` · `kPascal` constants |
| F23–F25 | header-only templates, `.cpp` walls · env + files keys (keychain later) · injectable clock |
| N1–N3 | Lua global `rhp` · `M.on_load` etc. as module fields · dotted lowercase patch ids |
| N4 | no default port |
| N5 | Win10 1809 · macOS 13 · iOS 16 · Android API 26 · glibc 2.31 |
| N6–N7 | ping 2 s / 3 misses / backoff 250 ms→30 s · unlimited clients |
| N8–N10 | log levels trace→critical · `host.on<>()` returns scoped subscription · `string_view` in / `string` out / UTF-8 |
| N11–N12 | full-featured rhp-cli · TOML-like identity file |
| N13–N16 | stale handle = Lua error · many hosts, no globals · process-wide patch/event registry · `Rhp::lua_event<"name", Args...>` |
| N17 | Stage 0 = folders + CMake + presets, `.clang-format` + `.editorconfig`, utils + core with tests, `Docs/decisions`, per-folder READMEs |

---

## 20. Decision log (round 3)

| # | Decision |
|---|---|
| R1 | run to completion everywhere (cancel flag is the escape hatch) |
| R2 | `pin(mod)` / `unpin(mod)` for admin; pinned modules survive disconnect |
| R3 | HTTP gateway state reverted after 5 min idle |
| R4 | `kAdmin` gets the full Lua standard library |
| R5 | ≤ 64 pending unauthenticated handshakes, 5 s timeout |
| R6 | lib names in mDNS only when the host opts in |
| R7 | off-pump-thread patch point hit → C++ default + miss counter |
| R8–R9 | `lua_event`: sync on pump thread, queued otherwise; fire-and-forget |
| R10–R11 | module names dotted lowercase · revision counter + hash in status |
| R12 | branch + PR per stage, conventional commits |
| R13–R14 | `Docs/decisions/<topic>.md` · tests `<thing>_tests.cpp` |
| R15–R16 | rhp-cli: replxx + CLI11 |
| R17 | `windows-msvc-asan` preset |
| R18 | chunk names `@module_name` |
| R19 | Stage 0 started |

---

## 21. Stage 1 implementation notes

Choices made while building Stage 1 that the questionnaires didn't cover. Each is recorded in the matching `Docs/decisions/` file.

| # | Topic | Decision |
|---|---|---|
| S1 | Local runtime | `Rhp::script::sandbox` is the per-identity runtime (one `lua_State`, one `_ENV` per module, one ledger). Stage 1 uses it directly; `Rhp::host` (Stage 3) owns one per identity. A local sandbox defaults to `role::kPatch` |
| S2 | Patch point declaration | `Rhp::patch_point<"id", &default_fn>`: the default is a template argument (§4.3), so state is `constinit` and registration happens before `main` |
| S3 | Out-of-order revert | variable writes and patch layers live in process-wide per-target stacks; undoing an older write hands its saved value to the next newer one, so any revert order restores exactly |
| S4 | Lib globals | each lib is a locked **userdata** proxy (`__index` / `__newindex`, `__metatable = "locked"`), so `rawset` can't bypass journaling; unknown reads are `nil`, unknown or read-only writes raise `kInvalidArgument` |
| S5 | Errors inside Lua | RHP raises strings formatted `[code] where: message`; when they reach C++ the original `Rhp::error` is recovered (`[code]` is parsed as a fallback) |
| S6 | Environments | a module's `_G` is its own `_ENV`; `load` is text-only for **every** role (admin included) and defaults to the caller's environment; non-admin `os` holds only `time` and `clock` |
| S7 | Stops | cancel and the instruction budget apply to runs (`exec`, `load`, `call`, and handlers they trigger). Once a stop fires the count hook switches to every instruction, so a script that keeps re-entering `pcall` still can't swallow it. Patch handlers hit from game code outside a run are not limited yet (Stage 2 scheduler) |
| S8 | Memory | the Lua allocator goes through `std::pmr`; the memory limit covers the whole `lua_State` and is sticky for the rest of a run; Lua's emergency GC reclaims afterwards |
| S9 | Engine concept | `puc_lua` is the only engine and `Rhp::script::stack` is the engine boundary; a formal `engine` concept for the `config<>::engine<>` slot arrives with a second engine |
| S10 | Deferred to Stage 2 | `Rhp::lua_event`, transactional reload (loading a loaded name returns `kAlreadyLoaded`), `require`, revisions, `on_save` / `on_restore` |
| S11 | `RHP_ENABLE=OFF` | Lua is not fetched or linked; the sandbox is an inert stub returning `kDisabled`; the DSL, the ledger and direct-call patch points still compile |

---

## 22. Decision log (round 4, Stage 2)

| # | Topic | Decision |
|---|---|---|
| T1 | Time slicing | opt-in only: `limits.slice_us = 0` stays the default; the Stage 2 "never blocks a frame" check runs with slicing on |
| T2 | Cancel vs waits | `cancel` kills the whole request: its coroutine, running or suspended. Timers are ledger effects: revert / unload removes them, cancel doesn't |
| T3 | Reload | overlap, then swap: the new revision runs while the old one is live, `on_restore(on_save())` carries state, then the old revision is reverted. A failure reverts only the new revision; the old one is untouched |
| T4 | Revisions | the last N sources (+ hash, counter) are kept; `rollback(mod, n)` is a reload of a stored source, so state carries through `on_save` / `on_restore` |
| T5 | `require` cycles | a cycle fails with a clear error; `require` returns a read-only live proxy that always reads the module's current exports |
| T6 | Force unload | without `force`: `kHasDependents`. With `force`: dependents stay loaded and touching the unloaded module raises `kUnloaded` |
| T7 | `rhp.emit` | `sandbox_options::on_emit` callback, called immediately on the pump thread, in order with `print`; emitted values are not part of the return list |
| T8 | Stubs | filtered by role: entries the role can't call are left out, variables are marked read-only for `observe`; the `rhp` API and module hooks are included |
| T9 | `lua_event` delivery | synchronous when fired on the sandbox's thread, queued to the next `pump()` otherwise; each handler is ledger-tracked |
| T10 | Handlers outside a run | every patch / event handler call that game code triggers is its own small run: cancel, instruction and wall budgets apply per call; a stop faults the module and the C++ default runs |
| T11 | Re-entrant lifecycle ops | `revert` / `unload` / `reload` / `rollback` / `revert_to` / `revert_all` called from inside a running script are queued and applied when the outermost run returns (or at the next `pump()` for handlers game code triggered); they report `deferred` |
| T12 | Workflow | main session writes the core; one subagent (no nested agents) writes stubs and tests; branch `stage-2-scheduler`, PR |

---

## 23. Stage 2 implementation notes

Choices made while building Stage 2 beyond the round-4 questionnaire (§22). Each is recorded in the matching `Docs/decisions/` file.

| # | Topic | Decision |
|---|---|---|
| U1 | Requests | every `exec` / `load` / `call`, timer callback and event handler is a **request**: a coroutine with its own instruction / wall budget. An operation whose request suspends returns early (`exec` / `call`: empty list, `load`: module `kLoading`, `reload`: revision 0) and the final result goes to `sandbox_options::on_result`; `last_request()` names it |
| U2 | Who may suspend | only a request's own thread, when yieldable. Patch handlers, `on_save` / `on_restore` / `on_unload`, coroutines a script created and callbacks of C functions (`table.sort`) can't; `rhp.wait` there raises `kInvalidArgument`. `coroutine.resume` / `close` refuse request coroutines |
| U3 | Frames and time | `rhp.wait(n)` counts `pump()` calls (n < 1 → 1); `rhp.sleep` and `rhp.timer` use the injectable `sandbox_options::clock`; limits always use `steady_clock`. A pump resumes only requests ready when it started, round robin, and stops once its slice is spent |
| U4 | Slices | `slice_us` applies per operation, per `pump()` and per synchronous event delivery from game code; the count hook yields only the request's own thread, so a loop inside a coroutine the script created can't be sliced (cancel and limits still stop it) |
| U5 | `wall_ms` | per request (summed over resumes) or per handler call; errc `kTimeout` |
| U6 | Revisions | each revision has its own `_ENV`; ledger entries carry module, revision and request (`effect_owner`), so a reload reverts exactly the old revision and a failed `exec` exactly its own request. Revision numbers are consumed by failed reloads too; `status` shows revision, CRC-32C source hash, revisions kept and `reloading` |
| U7 | Reload swap | the old revision's effects, timers, subscriptions and suspended requests go at the swap — including game-state writes; state crosses only through `on_save` / `on_restore`. `load` of a loaded name is a reload; `rollback(mod, n)` reloads a kept source as a new revision |
| U8 | Timers | `rhp.timer(ms, fn, repeating)` → id usable with `rhp.off`; a repeating timer fires at most once per pump and skips missed ticks |
| U9 | Faults | outside a run a failing request faults its module at once; inside a run, and for handlers game code triggered, at the end of the outermost operation or the next `pump()`. A stop of the surrounding run (cancel, a limit) never faults a handler's module |
| U10 | Events | `Rhp::lua_event<"name", Args...>` registers on first use of `fire`; arguments are `Rhp::convertible` or opaque handle types; `listeners()` counts subscribed sandboxes |
| U11 | Errors | new `errc::kUnloaded`; `Rhp::kLastErrc` marks the last code |
| U12 | Cancel delivery | a `cancel(request)` for a suspended request stays pending until that request would resume, which ends it instead (or the next operation / `pump()` does). `on_result` for timer and event requests carries no values; destroying a sandbox ends its suspended requests without `on_result` |

---

## 24. Decision log (round 5, Stage 3)

| # | Topic | Decision |
|---|---|---|
| W1 | Client scope | Stage 3 ships a **blocking** `Rhp::client<Cfg>` with every sandbox-backed op (`exec`, `load`, `call`, `reload`, `rollback`, `revert`, `unload`, `checkpoint`, `revert_to`, `revert_all`, `cancel`, `list`, `status`, `describe`) and `on_output` / `on_emit`; async calls, futures, `co_await`, `fleet` and `rhp-cli` are Stage 4 |
| W2 | Codec | RHP's own MessagePack codec for `Rhp::value` (`Rhp::wire::msgpack`): no dependency, counts and depth checked before allocating, easy to fuzz. msgpack-c is dropped (its Boost-free mode is still experimental); another codec can still plug into `config<>::codec<>` |
| W3 | Disconnect | without resume (Stage 5) a session ends when its link closes or its heartbeat dies (3 × 2 s); the identity's last session ending cancels its requests from the network thread, reverts and unloads everything and closes its `lua_State` |
| W4 | I/O threading | `exec::owned_io_thread` (default: one `std::jthread` runs Asio) and `exec::zero_threads` (`pump()` and blocking client calls poll the network) |
| W5 | Crypto | Monocypher 4.0.3 moves to Stage 3: the PSK mutual challenge-response derives per-direction keys, and every frame after the handshake carries a 32-byte keyed-BLAKE2b MAC over header + payload (seq inside, so replays fail) |
| W6 | Non-loopback | loopback addresses always; anything else fails with `kForbidden` unless the endpoint says `Rhp::net::insecure_lan` (until TLS in Stage 5) |
| W7 | Reliability | cumulative ack, an unacked resend window, CRC failure → nack → resend, a bounded idempotency-key response cache, ping/pong heartbeat; resume tokens and reconnect/backoff are Stage 5 |
| W8 | Example | new `Examples/remote_exec` (loopback, then TCP; three keys and roles); `hello_console` stays the local demo |
| W9 | Config | `Rhp::config<>` gets the Stage 3 slots only: transport, codec, auth, executor, io, limits, errors, clock, logger; TLS / signer / discovery slots come with their stages |
| W10 | Signing | Stage 3 runs unsigned scripts from any authenticated role; roles still gate what they can do. Signatures become mandatory (except for observe) in Stage 4 |
| W11 | Output routing | print / `rhp.emit` / results go to the session whose request caused them; output from timers, event handlers or requests whose session is gone goes to every live session of the identity (and the host logger at debug) |
| W12 | Workflow | the main session writes and tests everything; one subagent (no nested agents) reviews the finished stage for bugs at the end; branch `stage-3-wire-session`, PR |

---

## 25. Stage 3 implementation notes

Choices made while building Stage 3 beyond the round-5 questionnaire (§24). Each is recorded in the matching `Docs/decisions/` file.

| # | Topic | Decision |
|---|---|---|
| X1 | Compile once | `Rhp::host<Cfg>` / `Rhp::client<Cfg>` are thin templates: the config is type-erased into a `setup` (`net::transport_ops`, `wire::codec_ops`, a handshake factory, limits, logger, clock) and the engines (`host.cpp`, `client.cpp`) compile once. The session layer never sees a policy type: only `net::link`, `wire::codec_ops`, `security::host_handshake` / `client_handshake` and `wire::frame_sealer` |
| X2 | Modules | new folders: `platform` (OS name, secure random — the only OS `#ifdef`s), `wire`, `net`, `security`, `exec`, `session`, `config`, `host`, `client`. `net` depends on `platform` (not `wire`); `session` on `net`, `security`, `exec`, `wire`; `config` on all four policy layers |
| X3 | Messages | every request and reply payload is an `envelope {req, idem, body}`; `wire/messages.hpp` defines each body with an `Rhp::convert` specialization. A request gets exactly one `kResult` or `kError`; `kOutput` / `kEmit` carry the request id (0 = none). Modules are named by id or name (`wire::module_ref`). Decoders ignore unknown keys |
| X4 | Handshake | hello → challenge (host proof) → response (client proof, sent only after the host's proof checks out) → welcome, the first MAC'd frame. An unknown key name gets a normal challenge made with a random secret. Garbage before the handshake closes the connection at once; after it, three resync strikes |
| X5 | Frames | the 28-byte header of §8.1 with a 16-bit op; ops 1–15 handshake, 16–47 requests, 48–63 replies (sequenced), 64+ control (unsequenced: ping, pong, ack, nack); a session-ending error is an unsequenced `kError` (sealed once keys exist). `kWelcome` joins the op list; `kResume`, `kPin`, `kUnpin`, `kBlob` are reserved |
| X6 | Nack | a nack's `ack` field is the last good seq: the peer resends everything after it (one nack per gap). A whole heartbeat without ack progress also resends the window, covering a lost nack |
| X7 | Identities | a sandbox per identity is created when its first session is welcomed (caller role = the key's role, every installed lib) and destroyed — `revert_all`, then closed — when its last session ends. Sessions of one identity share it (and its scratch module) |
| X8 | Cancel path | `kCancel` never goes to `pump()`: the network thread applies it through a per-identity *cancel relay* (mutex; cleared before the sandbox dies) that **records** it — per session: cancelled request ids, a cancel-all mark over the network's arrival order, and `dead` once the session ends. The record stops the request running in `pump()` (`sandbox::cancel()`, re-applied every 20 ms because a cancel landing just before the sandbox opens its run scope is cleared by it), suspended ones (`sandbox::cancel(request)`, also checked when a request suspends), and queued ones (answered `kCancelled` without running; a dead session's are dropped). A session that ends stops its own requests even when its identity lives on |
| X9 | Suspended requests | a request whose script suspends (`rhp.wait`, `rhp.sleep`, a time slice) is answered when `sandbox_options::on_result` reports it; the sandbox gained `pending(request)` and a request-aware `on_output` for this |
| X10 | Idempotency | per session, keyed by the client's `idem` (63 random bits): a retry of a finished request is answered from the cache (256 entries), a retry of one in flight waits for the same result |
| X11 | Limits | a reply larger than `max_frame` becomes a `kLimitExceeded` error for that request; an oversized request fails on the client. At most `pending_handshakes` (64) unauthenticated connections; more are closed at once. Before the handshake frames may carry 16 KiB. The MessagePack decoder caps total values (`decode_limits::max_elements`, 2^20) and never reserves more than 256 slots on a count's word. Per session: 4096 requests in flight with an idempotency key, 65 536 held back while `pump()` is behind, 256 / 16 MiB of cached replies — past those the session is closed with `kLimitExceeded`. An exception while receiving ends that session, not the network thread |
| X12 | TCP | `TCP_NODELAY` on every socket; `SO_REUSEADDR` only off Windows (there it would allow port stealing); port 0 = any free port, reported by `host.port()` |
| X13 | Reverse mode | Stage 3 hosts listen and clients dial; the other directions fail with `kInvalidArgument` until Stage 4 |
| X14 | Core additions | `Rhp::value_list`; `Rhp::convert` for `strong_id` (as an integer) and `Rhp::error` (a map; unknown code names decode as `kRuntime`) |
| X15 | `RHP_ENABLE=OFF` | `wire`, `platform`, `config`, `exec` and keys / keyring still build and test; `net`, `session` and the PSK handshake compile to headers only; Asio and Monocypher are not fetched; `Rhp::host` / `Rhp::client` are inert (`kDisabled`) |
| X16 | Monocypher | compiled as C++ through one wrapper translation unit (like Lua), so RHP still needs no C toolchain |
| X17 | Control frames | ping, pong, ack and nack carry their own per-direction counter in `seq` (sealed), so a replayed one is dropped |
| X18 | `zero_threads` clients | the network only runs while a call waits or `client::poll()` runs; an idle client must poll at least once per heartbeat or the host ends its session (and reverts it) |
| X19 | Review | an end-of-stage review (one subagent) found ten issues — a full SPSC ring wiping the item it refused, lost cancels (incl. a disconnect that left a `while true` running for good), MessagePack reserve amplification before authentication, idle `zero_threads` clients dropped, unbounded in-flight / backlog state, event output misrouted, replayable control frames, TCP write-buffer lifetime, loopback posts into a dying context — all fixed with regression tests |

---

## 26. Decision log (round 6, Stage 4)

Taken without a questionnaire: the user asked for Stage 4 to be planned and built straight away, so at each choice the implementer took the option the earlier rounds pointed to (or the conventional default) and recorded it here.

| # | Topic | Decision |
|---|---|---|
| Y1 | Workflow | the main session writes and tests everything; one subagent (no nested agents) reviews the finished stage for bugs at the end; branch `stage-4-tooling`, PR |
| Y2 | Signing | standard Ed25519 (RFC 8032, Monocypher's optional implementation) over `"rhp/script\0" ‖ source`; a signature is `{signer, sig}`; `config<>::signer<S>` slot (concept `Rhp::security::signer`), default `ed25519`; `Rhp::security::unsigned_scripts` is the typed opt-out; hosts take `trusted_signers` next to their authenticator |
| Y3 | What is signed | the source of `exec`, `load`, `reload` from patch and admin sessions; observe may run unsigned code (F7–F8) but a signature that is present must verify; `call` and `rollback` carry no new code |
| Y4 | Audit | `host.on<E>()` / `on_any()` return scoped subscriptions; events `session_opened`, `session_closed`, `auth_failed`, `script_executed` (every request that runs code or changes state, refused ones included), `blob_received`, `identity_reverted`, delivered on the pump thread; `Rhp::audit::file_sink` / `ostream_sink` write JSON lines; hashes BLAKE2b-256 hex (F19) |
| Y5 | Blobs | chunked per message (op `kBlob`, `client_options::blob_chunk` 1 MiB, `blob_window` 4 in flight), each chunk a request; sink and role (admin unless the sink says otherwise) checked on the first chunk before anything is buffered; whole blob to the sink on the pump thread, ≤ `limits.max_blob` (0 = only empty blobs); one transfer per session — a new transfer replaces one the client gave up on; frame-level `kMore` stays reserved |
| Y6 | Reverse mode | a dialing host redials with capped exponential backoff + full jitter; a listening client serves one host at a time and survives its host; `client::port()`; resume stays Stage 5 |
| Y7 | Pin | admin, own identity; the identity's sandbox outlives its sessions while it has pinned modules; at the last disconnect the rest (scratch + modules the pinned ones don't require) is reverted and unloaded; `revert` / `unload` of a pinned module and `revert_to` while any module is pinned → `kForbidden`; a call running in a pinned module isn't stopped by its session ending (only by an explicit cancel); `revert_all` clears pins and closes sessionless identities |
| Y8 | Async client | `Rhp::pending<T, Errors>` per call (then / get / future / `co_await`, consumed once); `client.async()` mirrors the blocking ops; `exec_async` / `exec_future`; `cancel(request)`; no task type is shipped (any C++20 coroutine can await); `fleet` is Stage 6 |
| Y9 | rhp-cli | replxx + CLI11 (R15–R16); subcommands `keygen`, `pubkey`, `sign`, `connect`, `run` (`--pin`, `--name`), `exec`, `stubs`, `blob`, `watch`; REPL with multi-line Lua (block / bracket heuristic), tab completion from `describe` + `list`, history, colors, Ctrl+C = cancel; a non-terminal stdin is a script; `--listen` = reverse mode |
| Y10 | Key files | identity file (N12) `name`, `psk`, `signing_key`, optional `signer`; host files: keyring `name role base64-psk`, trusted signers `name base64-public-key` — exactly what `keygen` / `pubkey` print |
| Y11 | Kill switch | `host.set_enabled(false)` at runtime: new connections closed, requests answered `kDisabled` |
| Y12 | Protocol | `kProtocolRevision` 2 (signatures, pin / unpin, blobs) |
| Y13 | Example | `Examples/headless_server`: a standalone host (key files, audit log, blob folder, reverse mode) that the CLI tests drive as a separate process |

---

## 27. Stage 4 implementation notes

| # | Topic | Decision |
|---|---|---|
| Z1 | Ed25519 split | `signing_keys.cpp` (key bytes, base64, the signers file — pure C++) + `ed25519.cpp` (Monocypher) or `ed25519_disabled.cpp` (`RHP_ENABLE=OFF`: signing / verifying report `kDisabled`), so OFF builds still take trusted signers and identity files |
| Z2 | Modules | new `event` (layer 3, core only) and `audit` (layer 4); `host` depends on `event`; `Tools/rhp-cli` is `rhp_cli_core` (text helpers + `shell<Cfg>`) and the `rhp-cli` executable |
| Z3 | Audit timing | `script_executed` is reported when the request is handled; a request that suspends reports `kOk` then (its final result only goes to the client); `reply_error` fills in the outcome of the request being audited |
| Z4 | Async before ready | an async call made before the session is ready is queued and sent once it is (or failed when the session closes); `client_options::request_timeout` arms a per-call timer for async calls; a closed client answers at once on the calling thread |
| Z5 | Pin and the relay | a released identity's cancel relay drops its sandbox (no session can cancel); a new session of that identity hands its fresh relay the sandbox |
| Z6 | Blob refusal | after a refused chunk, later chunks of that transfer are refused quietly (`kCancelled`, no second event) so a pipelined window doesn't spam the log |
| Z7 | rhp-cli parsing | in quoted words only `\"` is an escape, so Windows paths keep their backslashes; Lua completeness counts `function` / `do` / `if` / `repeat` against `end` / `until`, brackets, long strings and comments |
| Z8 | rhp-cli tests | `Tests/tools`: the shell in-process over loopback (every command, watch, completion, Ctrl+C), then the real binaries as processes (`std::system`) against `headless_server` over TCP, including reverse mode |
| Z9 | replxx | upstream's last commit is from 2021 (`release-0.0.4`); kept per R15 — it builds warning-free under our own target on MSVC 19.51, clang-cl 22 and Clang 21, and reads plain lines when stdin isn't a terminal |

| Z10 | Review | an end-of-stage review (one subagent) found nine issues, six confirmed with repros: async calls that had already failed (timed out, cancelled, or failed with their session) still went out once a session became ready; a cancelled or disabled blob chunk left its transfer half-open, blocking every later blob on that session; the MSVC runtime resetting the SIGINT handler, so a second Ctrl+C killed `rhp-cli` (and the host reverted its work); a disconnect faulting a pinned module through a call its session had started; `revert_to` undoing pinned modules; identity files created world-readable on POSIX; unfinished multi-line Lua impossible to abandon at the prompt and silently dropped at end of input; a listening client failing its queued calls when a connection that never authenticated closed; observe sessions' unsigned code able to hold the pump thread under default (unlimited) limits — documented. All fixed with regression tests, plus nits: quoted `call` arguments stay strings, invalid UTF-8 in audit lines becomes U+FFFD, refused connections are reported as `auth_failed`, `headless_server` logs the reverts it does at shutdown and accepts only plain blob file names, a client closed before it started stays closed |

## 28. Decision log (round 7, Stage 5)

Taken without a questionnaire: the user asked for Stage 5 to be planned and built straight away, like Stage 4, so each choice took the option earlier rounds pointed to (or the conventional default) and is recorded here.

| # | Topic | Decision |
|---|---|---|
| AA1 | Workflow | the main session writes and tests everything; one subagent reviews the finished stage at the end; branch `stage-5-hardening`, PR |
| AA2 | TLS shape | a sans-IO `Rhp::security::tls::engine` (ciphertext in and out through buffers) behind the `tls::backend` concept (`server(settings)` / `client(settings)` → a `context` that makes one engine per connection); `config<>::tls<B>` slot, default `tls::auto_backend`; `tls::none` builds without TLS. A link decorator (`session::tls_client` / `tls_server`) puts TLS over any transport, user transports included — no Asio SSL streams, so both backends share one path |
| AA3 | Backends | OpenSSL is the system's (≥ 3.0, found by CMake, desktop only) — never built from source, which needs Perl and NASM; Mbed TLS 4.2.0 comes from its release tarball through CPM (generated files included, no Python) and is built whenever `RHP_TLS_MBEDTLS` (mobile, the fallback without OpenSSL, interop tests). `auto_backend` = OpenSSL where found, else Mbed TLS. Round 1 said "OpenSSL 4.0.x": the OS's 3.x or 4.x is used instead |
| AA4 | Trust | TLS 1.3 only, no session tickets. The host's certificate is `host_options::tls.cert_pem` + `key_pem`, or an ephemeral self-signed P-256 one made at start. Clients don't check it by default: the PSK proofs and frame keys include the RFC 9266 tls-exporter value, so a relay that terminates TLS on both sides can't authenticate (mTLS stays rejected). `client_options::tls.ca_pem` (+ `server_name`) turns on certificate verification. Authenticators get the binding through `bind_channel()`; one that ignores it is open to such relays unless the client checks certificates |
| AA5 | When TLS | `endpoint::tls`: `kAuto` (default) or `kRequire` (`Rhp::net::require_tls`). Dialing: TLS when required, or over a network transport (`T::network`, TCP) to a non-loopback address without `insecure_lan`. Listening: the first byte decides (0x16 → TLS); plaintext only from loopback peers (`link::loopback()`), over local transports, or with `insecure_lan` — never with `require_tls`. Building without a backend makes such endpoints `kForbidden` |
| AA6 | CRC under TLS | frames on an encrypted link carry no CRC (`kCrcOmitted`); a CRC-less frame on a plaintext link ends the session |
| AA7 | Resume | `limits.resume_ms` (6000; 0 = off). A lost link — or a heartbeat that died, i.e. a half-open link — detaches the session instead of ending it; requests and replies keep queueing. The dialing side redials (capped backoff, full jitter) and sends `kResume {session, proof}` sealed with the session's MAC key under the next control counter (replay-proof, nothing secret on the wire), where `proof` is the sender's frame MAC over `"rhp/resume"` and the new connection's channel binding — a relay that terminates TLS on the new connection can't carry it through; the other side's new connection hands its link to that session, which answers with a sealed `kWelcome {session, proof}` bound the same way; both resend what the other hasn't acknowledged. Exactly once comes from the existing seq/ack. Not back in time: the session ends with the link's error and its identity is reverted as before. Works in reverse mode (the host redials) |
| AA8 | Goodbye | a host that shuts down closes its sessions with a reason ("the host is shutting down", `kTransport`) and waits up to 500 ms for that to go out, so clients fail at once instead of trying to resume |
| AA9 | Fuzzing | targets frame (decoder over arbitrary chunking, re-encode round trip), envelope (every wire message type), msgpack (canonical round trip) and sandbox_escape (observe-role Lua with limits: host state untouched, hidden globals stay hidden); `RHP_FUZZ=ON` (Clang, preset `linux-clang-fuzz`) builds libFuzzer executables; every build runs replay drivers in ctest (seeds + 3000 deterministic mutations) |
| AA10 | Mobile presets | Android presets take `ANDROID_NDK_HOME`; `Tools/android/run_tests.py` pushes the test executables to a device or emulator and runs them; `ios-sim` runs tests through `Tools/ios/simctl_run.sh` (`CMAKE_CROSSCOMPILING_EMULATOR`); a GitHub Actions workflow builds and tests Linux (Clang, ASan+UBSan, TSan), Windows (MSVC, clang-cl), macOS, the iOS simulator (+ an iOS device build) and Android (x86_64 on an emulator, arm64 build) |
| AA11 | Protocol and events | `kProtocolRevision` 3 (resume, CRC-less frames); events gain `session_resumed`, and `session_opened.tls` |

---

## 29. Stage 5 implementation notes

| # | Topic | Decision |
|---|---|---|
| AB1 | Mbed TLS threading | its PSA core isn't thread-safe in the default configuration, and Windows has no ready threading layer: every Mbed TLS call takes one process-wide recursive lock (a handful of links don't notice) |
| AB2 | Moving a link | a session receives its link's callbacks through a small `link_port` that can be re-pointed, so a link moves from the new connection's session to the one it resumes; replaced links are kept (`retired_`) until they are surely outside their own callbacks |
| AB3 | The resume connection | the session that only carried a resume ends with `errc::kOk` ("resumed session N"): hosts don't count it as a failed authentication |
| AB4 | Resend | unacknowledged frames are kept as payloads and encoded again when resent (the ack and whether the link wants a CRC may have changed) |
| AB5 | Who speaks first | the accepting side holds what its session sends until the peer's first byte (TLS or not); a host that dials (reverse mode) opens with an unsealed ping, which handshakes ignore |
| AB6 | Reverse-mode client | while it has a session it keeps new connections as candidates (at most 4): a resume goes to the session; a full handshake replaces a session that is detached (the host restarted) and is refused otherwise |
| AB7 | Expiry | a session not resumed in time ends with its link's error code (`kTransport`, or `kTimeout` for a dead heartbeat) and "(not resumed within N ms)" |
| AB8 | Fuzz finding | sandbox_escape: converting a deeply nested Lua table to `Rhp::value` used more stack slots than Lua guarantees a C function (`lapi.c` assertion in Debug builds, an overrun in Release) — `lua_checkstack` per level |
| AB9 | Build | Mbed TLS enables C, so the Windows and Linux presets name the C compiler too (`cl`, `clang-cl`, `clang`); `RHP_ENABLE=OFF` still fetches only Catch2 (the TLS module builds factories that report `kDisabled`) |
| AB10 | Android on hardware | with `-DRHP_BUILD_TESTS=ON` the `android-arm64` build runs on a phone through `run_tests.py`: every suite — integration (TLS, resume) and the fuzz replays included — passed on an arm64 device with Android 16 (API 36) |
| AB11 | Review | the end-of-stage review (one subagent) found: (high) a resume was not bound to the new TLS connection, so a relay terminating TLS on the redial could carry a valid `kResume` through and read everything after it — both resume frames now carry a proof over the new connection's channel binding, and a test runs a resume through such a relay (refused) and through a plain relay (works); (medium) application data arriving in the same read as a TLS close_notify or alert was dropped, so a host's goodbye over TLS could be lost — it is delivered first now; a resume attempt had no time limit of its own (a link that connects and never answers ate the whole window) — each attempt gets min(handshake_timeout_ms, 2 s); errors on a resume link (an unsealed `kError`, garbage, a bad MAC) ended the session — they now give up that link and try another; the macOS universal CI build linked arm64-only Homebrew OpenSSL — it uses Mbed TLS; (low) handshake failures were reported as certificate failures when nothing was being verified, and OpenSSL's per-thread error queue could fail the next handshake once — `kAuth` only when verifying, the queue is cleared before every call; a peer could hide a failed login from `auth_failed` by closing with `kError{ok}` — hosts check `session::handed_over()` instead; with `ca_pem` and no `server_name` the dialed name is now checked. Documented, not changed: idle unauthenticated connections count against `pending_handshakes` (and a listening client's 4 candidates) and can delay a resume; a session closed while detached tells nobody (the peer's window runs out); a probe can tell a known session id from an unknown one (`kAuth` vs `kNotFound`) |
| AB12 | Test hardening | the Stage 2 time-slice test assumed one `pump()` drains every request; under CPU load a 2 ms slice can be preempted, so it pumps (at most 50 times) until done |

## 30. Decision log (round 8, Stage 6)

Detailed rationale and primary sources: [Stage 6 networking decisions](decisions/stage6-networking.md). Usage: [networking and fleet](guide/networking.md).

| # | Topic | Decision |
|---|---|---|
| AC1 | Policy boundaries | WebSocket, reliable UDP and local IPC implement the existing transport concept. DNS-SD uses the new `discovery<D>` slot. HTTP feeds the host dispatcher as an optional frontend; fleet retains ordinary client instances. |
| AC2 | WebSocket | own RFC 6455 binary framing at `/rhp`; client masking, continuations, control frames and close handshake. TLS stays inside the byte tunnel, preserving the session channel binding. Conventional WSS and browser clients are outside this transport's contract. |
| AC3 | Reliable UDP | 480-byte fragments, random connection tokens, selective ACK, CRC32C, retransmission and congestion backoff reconstruct the ordered stream. TLS and session resume remain above it. FEC is optional and confined to this transport. |
| AC4 | IPC | owner-restricted overlapped named pipes on Windows; mode-0600 AF_UNIX sockets and inode-checked cleanup on POSIX; same-UID abstract AF_UNIX on Linux/Android. Authentication remains mandatory. |
| AC5 | HTTP | timestamp/nonce request MAC plus the existing script signature; MessagePack arguments/results; logical sessions share the identity's sandbox, roles, deferred replies, cancellation, pins and cleanup. Idle expiry defaults to five minutes. |
| AC6 | Discovery | advertisement is opt-in; library names require another opt-in. Windows native browsing resolves both native wildcard services and wire-owned constrained address records. Apple owns native A/AAAA and service records. Linux/native Android use the wire provider; APKs may supply an NSD policy. |
| AC7 | Fleet | start every signed request before collecting; return an outcome per host with a shared broadcast deadline. Keep resumable sessions, replace terminally closed clients, and progress all members during zero-thread waits and discovery. |

## 31. Stage 6 implementation notes

| # | Topic | Implementation |
|---|---|---|
| AD1 | Module layout | Asio remains private to backend translation units. The host's HTTP frontend is isolated in `gateway.cpp`, feeding the existing inbox/outbox and dispatcher. No second script engine or dependency copy is introduced. |
| AD2 | Input bounds | shared HTTP header parser: 16 KiB/64 fields, explicit Content-Length, no transfer coding or pipelines. DNS: 9000-byte packets, 128 records, 1024 cached records. UDP queues: 16 MiB, 64 receive fragments, 4096 close tombstones. |
| AD3 | Shutdown | closing links drain final bytes after their wrapper is released; refused unstarted UDP peers do not retain drain timers. FIN acknowledgments remain recoverable for 12 seconds. IPC removes only its own socket inode. Native DNS callbacks retain their contexts through cancellation. |
| AD4 | Gateway admission | native sessions and HTTP share the unauthenticated-handshake budget; successful request proofs release the slot before script execution, so suspended scripts do not prevent authenticated cancellation. |
| AD5 | Validation | regression coverage includes loss/corruption/duplication/reordering, raw WebSocket interoperability, deferred HTTP replies/reload/cancel/expiry, surviving sessions and pins, fleet mixed outcomes/recovery, zero-thread progress, and separate-process TLS broadcasts through real DNS-SD. Actual platform results are recorded in [Status and TODO](TODO.md). |
| AD6 | Review: codecs | WebSocket and reliable-UDP wire formats moved into sans-IO `detail/` codecs (`ws::decode_header`/`encode_frame`, `rudp::decode_packet`/`encode_packet`), unit-tested and fuzzed; typed opcodes, DNS record types and close codes replace magic numbers; one `dns_sd_service()` replaces four copies of the service-type ternary; base64 is one `utils/base64.hpp`. |
| AD7 | Review: transports | WebSocket streams data payloads instead of buffering whole frames and fixes its role at compile time; `close()` during the upgrade no longer drops queued bytes. Reliable UDP: RFC 6298 timeout, SACK fast retransmit and one backoff per batch (the loss test went from 1.7 s to 0.2 s), deadline-armed timers instead of 25 ms polling, one receive buffer per socket instead of a 64 KiB allocation per datagram, a 1024-peer cap per socket. IPC dialers use `SECURITY_IDENTIFICATION`; Linux checks the peer UID for pathname sockets too. |
| AD8 | Review: discovery | The wire provider is a CRTP `multicast_endpoint` shared by a `responder` and a `querier`. It no longer blocks the I/O thread on DNS, stops periodic 30 s announcements and per-second queries (RFC 6762 §5.2/§8.3), recovers from a conflict on `update()`, re-announces an unchanged name without probing, and keeps receiving after a per-datagram error. |
| AD9 | Review: HTTP | Unknown key names cost the same work (decoy key), closing a timing probe of key names. Per-key replay quotas, expiry-ordered pruning; a request in flight keeps its identity alive and a hung-up client cancels its own request (the first cut reverted running work after 5 minutes); per-request cancel tokens; `X-RHP-Signature` carries the signer's value so custom signers work; `Expect: 100-continue`; a status per error class. The engine implements a typed `gateway_sink`, and gateway/net detail types no longer reach `host.hpp`. |
| AD10 | Review: tests | Stage 6 unit tests follow the module layout (`websocket_tests.cpp`, `udp_reliable_tests.cpp`, `local_ipc_tests.cpp`, `http_tests.cpp`, `mdns_tests.cpp`); `[multicast]` cases share a ctest `RESOURCE_LOCK` (they collided on UDP 5353 under `ctest -j`); expiry tests wait for the HTTP session's close event instead of sleeping. |

## 32. Stage 6 completion notes

Taken without a questionnaire: the user asked for the Stage 6 follow-ups to be finished straight away, so each choice took the option the earlier rounds pointed to and is recorded here. Open items and platform results: [Status and TODO](TODO.md).

| # | Topic | Implementation |
|---|---|---|
| AE1 | Runtime defects | The four defects reproduced in the 2026-10-09 review are fixed with regressions. `pending`'s awaiter records its coroutine handle before publishing it (TSan caught the first cut writing it afterwards) and unregisters it when a suspended frame is destroyed, so a later completion keeps the result instead of resuming freed memory; destroying the coroutine must still not race with its completion. Patch points reject defaults returning `std::string_view`, also inside `std::optional`, at compile time: a Lua override's result string is unrooted once the handler returns (user `convert<T>::pull` types must own their data). `ledger`'s move assignment undoes the destination's effects first and leaves the source empty. A suspended request's `script_executed` record waits in its identity until the request finishes and then reports the final outcome; at teardown it is reported as `kCancelled`. |
| AE2 | HTTP channel binding | Opt-in per request: `X-RHP-Channel: tls-exporter` appends the header value and the connection's RFC 9266 exporter value (both length-prefixed) to the request MAC; the host appends its own, so a TLS-terminating relay fails the proof with 401. Unbound transcripts are unchanged and can't collide with bound ones (the body's length prefix fixes where it ends). Opt-in keeps plain HTTP clients and TLS-offloading front ends working; `host_options::http_require_binding` makes it mandatory (a signed 401 for unbound requests). |
| AE3 | HTTP answer proofs | Every answer to a request whose proof checked out carries `X-RHP-Proof`: keyed BLAKE2b-256 over `rhp/http-answer\0`, the status and the length-prefixed content type and body, under `keyed-BLAKE2b(psk, "rhp/http-answer-key\0" ‖ request MAC)`. The authenticator supplies the key in `http_grant::answer_key` (custom authenticators may leave it empty: no header). `security::verify_http_answer` checks an answer against the Authorization header of its own request. The host keeps no per-client state for it. |
| AE4 | Gateway clock | Idle expiry follows `config<>::clock` through its offset from `steady_clock`, which `pump()` samples into an atomic: the network thread never calls the user's clock. With a custom clock the idle timer re-checks every 25 ms. Proof freshness and the replay window stay on the system clock: the review found that shifting them with the host clock rejected every real client of a clock on another time base, and that a clock jumping ahead and back reopened the window for replays. |
| AE5 | HTTP audit | `script_executed` has a `peer` field for every request (JSON `"peer"`); over HTTP it is that request's caller rather than the first caller of the key. |
| AE6 | Fleet engine | `Rhp::fleet<Cfg>` is a thin template over `fleet_detail::engine` (`client/fleet.cpp`). Members are client engines on the fleet's single `net::io_context` (`client_detail::setup::shared_io`), run by one I/O thread for the whole fleet (`owned_io_thread`) or by the broadcasts, `discover()` and `poll()` (`zero_threads`). An engine on a shared reactor never runs it; its posts and dial/accept completions check a liveness token, and it is destroyed on the reactor's thread (posted, after its own queued work) or once the reactor stopped. `exec`, `load` and `call` (module by name: ids differ per host) share one path: sign once, submit everywhere, collect within one deadline, cancel late requests, return outcomes in member order. `Rhp::client<Cfg>` is unchanged. |
| AE7 | Tests | `stage6_fleet_tests.cpp` covers load/call broadcasts, signing, the shared deadline and one network thread per fleet (`on_output` thread ids). The fleet recovery test keeps one listener bound for the whole test (`tcp_gate`) instead of re-binding a released port. A TCP relay that terminates TLS (optionally rewriting answers) covers binding and answer proofs end to end. `[multicast]` cases carry the ctest label `multicast` (`ctest -LE multicast` on machines without usable multicast). Expiry tests wait for the revert as well as `session_closed` (published first); the CLI fleet test uses per-run DNS-SD instance names; the suspended-at-revert audit test waits for the script's own output instead of sleeping. |
