#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/detail/patch_layers.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/lua_internals.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/utils/fixed_string.hpp>

namespace Rhp::script {

namespace detail {

sandbox_impl& impl_of(lua_State* L) noexcept {
    return static_cast<sandbox_impl&>(**static_cast<context**>(lua_getextraspace(L)));
}

namespace {
constexpr double kMaxMilliseconds = 1e12; // ~31 years: keeps duration conversions in range
} // namespace

steady::duration milliseconds(double ms) {
    return std::chrono::duration_cast<steady::duration>(std::chrono::duration<double, std::milli>{std::min(ms, kMaxMilliseconds)});
}

double checked_ms(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto ms = s.to_number(index);
    if (!ms || !(*ms >= 0.0)) {
        s.raise(make_error(errc::kInvalidArgument, std::format("expected milliseconds >= 0, got {}", s.type_name(index)), std::string{where}));
    }
    return *ms;
}

namespace {

constexpr std::size_t kAlignment = alignof(std::max_align_t);

// The alloc_kind of a new block from the tag Lua passes as its old size (the object's basic type).
constexpr std::size_t alloc_kind_of(std::size_t tag) noexcept {
    switch (tag) {
    case LUA_TSTRING: return static_cast<std::size_t>(alloc_kind::kString);
    case LUA_TTABLE: return static_cast<std::size_t>(alloc_kind::kTable);
    case LUA_TFUNCTION: return static_cast<std::size_t>(alloc_kind::kFunction);
    case LUA_TUSERDATA: return static_cast<std::size_t>(alloc_kind::kUserdata);
    case LUA_TTHREAD: return static_cast<std::size_t>(alloc_kind::kThread);
    case LUA_NUMTYPES: return static_cast<std::size_t>(alloc_kind::kUpvalue);       // LUA_TUPVAL
    case LUA_NUMTYPES + 1: return static_cast<std::size_t>(alloc_kind::kPrototype); // LUA_TPROTO
    default: return static_cast<std::size_t>(alloc_kind::kOther);
    }
}
constexpr std::uint32_t kDefaultCheckInterval = 1'000;
// Finished requests whose map node, record and coroutine wait for reuse: enough for a frame's worth
// of handler calls without holding on to a burst.
constexpr std::size_t kSpareRequests = 64;
constexpr const char* kModuleProxyKey = "rhp.module";             // metatable of require() proxies
constexpr const char* kModuleProxiesKey = "rhp.module_proxies";   // registry: module id → its proxy
constexpr const char* kRequestThreadsKey = "rhp.request_threads"; // registry: weak set of request coroutines

// Every load / reload request runs this: the module's top level, then on_load, then the exports.
constexpr std::string_view kLoaderSource = R"lua(
local type = type
return function(chunk, env)
    local exports = chunk()
    if type(exports) ~= "table" then
        exports = env
    end
    local on_load = exports.on_load
    if type(on_load) == "function" then
        on_load()
    end
    return exports
end
)lua";

int on_panic(lua_State* L) {
    const char* message = lua_tostring(L, -1);
    std::fprintf(stderr, "[rhp critical] unprotected Lua error: %s\n", message != nullptr ? message : "(no message)");
    std::abort();
}

// Runs a callable inside lua_pcall, so every Lua API call it makes is protected (an allocation
// failure under a memory limit becomes an error result instead of a panic).
template <class F>
result<void> protect(lua_State* L, F&& fn) {
    struct holder {
        std::remove_reference_t<F>* fn;
    } h{&fn};
    return stack{L}.run_protected(
        [](lua_State* inner) -> int {
            (*static_cast<holder*>(lua_touserdata(inner, 1))->fn)();
            return 0;
        },
        &h);
}

std::uint32_t source_hash(std::string_view source) noexcept {
    return utils::crc32c(utils::bytes_view{reinterpret_cast<const std::byte*>(source.data()), source.size()});
}

// ---- Lua-side builtins ---------------------------------------------------------------------------

// print(...) → the sandbox's output callback, arguments joined by tabs.
int lua_print(lua_State* L) {
    const int n = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= n; ++i) {
        std::size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) {
            line.push_back('\t');
        }
        line.append(s, len);
        lua_pop(L, 1);
    }
    std::optional<error> thrown;
    try {
        impl_of(L).output_line(line);
    } catch (const std::exception& e) {
        thrown = make_error(errc::kRuntime, e.what(), "print");
    }
    if (thrown) {
        stack{L}.raise(*thrown);
    }
    return 0;
}

// load(chunk [, chunkname [, mode [, env]]]): text chunks only, for every role; without an env
// argument the chunk sees the calling module's environment instead of the shared base table.
// Upvalue 1: the standard load.
int lua_safe_load(lua_State* L) {
    const int argc = lua_gettop(L);
    lua_settop(L, 4); // pad missing arguments with nil so indices 1..4 are stable
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_pushliteral(L, "t");
    if (argc >= 4) {
        lua_pushvalue(L, 4);
    } else {
        lua_rawgeti(L, LUA_REGISTRYINDEX, impl_of(L).current_env());
    }
    lua_call(L, 4, LUA_MULTRET);
    return lua_gettop(L) - 4;
}

// coroutine.resume / coroutine.close, refusing request coroutines: only the scheduler resumes them.
// Upvalue 1: the standard function.
int lua_guarded_coroutine(lua_State* L) {
    if (lua_type(L, 1) == LUA_TTHREAD) {
        lua_getfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
        lua_pushvalue(L, 1);
        const bool request = lua_rawget(L, -2) != LUA_TNIL;
        lua_pop(L, 2);
        if (request) {
            stack{L}.raise(make_error(errc::kInvalidArgument, "this coroutine is a script request; only the scheduler resumes it"));
        }
    }
    lua_State* co = lua_tothread(L, 1);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
    if (co != nullptr) {
        impl_of(L).credit_hook_progress(co); // the instructions it ran since its last hook tick
    }
    return lua_gettop(L);
}

// rhp.patch(id, handler): overrides a C++ patch point until the calling module is reverted.
int lua_rhp_patch(lua_State* L) {
    stack s{L};
    auto& impl = impl_of(L);
    if (!allows(impl.caller_role(), role::kPatch)) {
        s.raise(make_error(errc::kForbidden, std::format("needs role {}", role::kPatch), "rhp.patch"));
    }
    const auto id = s.to_string(1);
    if (!id) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a patch point id, got {}", s.type_name(1)), "rhp.patch"));
    }
    std::optional<error> failure;
    {
        auto point = find_point(*id);
        if (!point) {
            failure = std::move(point).error();
        } else {
            auto fx = (*point)->attach_lua(s, 2);
            if (!fx) {
                failure = std::move(fx).error();
            } else {
                impl.record_effect(std::format("patch {}", *id), std::move(*fx));
            }
        }
    }
    if (failure) {
        if (failure->where.empty()) {
            failure->where = "rhp.patch";
        }
        s.raise(*failure);
    }
    return 0;
}

// rhp.wait([frames]): suspends the request for `frames` pump() calls (at least 1).
int lua_rhp_wait(lua_State* L) {
    const stack s{L};
    std::int64_t frames = 1;
    if (!s.is_none_or_nil(1)) {
        const auto n = s.to_integer(1);
        if (!n) {
            s.raise(make_error(errc::kTypeMismatch, std::format("expected a frame count, got {}", s.type_name(1)), "rhp.wait"));
        }
        frames = std::max<std::int64_t>(*n, 1);
    }
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.wait").wake_frame = impl.frame() + static_cast<std::uint64_t>(frames);
    return lua_yield(L, 0);
}

// rhp.next_frame(): suspends the request until the next pump().
int lua_rhp_next_frame(lua_State* L) {
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.next_frame").wake_frame = impl.frame() + 1;
    return lua_yield(L, 0);
}

// rhp.sleep(ms): suspends the request until the script clock has advanced `ms` milliseconds.
int lua_rhp_sleep(lua_State* L) {
    const double ms = checked_ms(L, 1, "rhp.sleep");
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.sleep").wake_time = impl.script_now() + milliseconds(ms);
    return lua_yield(L, 0);
}

// rhp.frame(): pump() calls so far.
int lua_rhp_frame(lua_State* L) {
    lua_pushinteger(L, static_cast<lua_Integer>(impl_of(L).frame()));
    return 1;
}

// rhp.emit(value): streams a value to the host (sandbox_options::on_emit).
int lua_rhp_emit(lua_State* L) {
    const stack s{L};
    std::optional<error> failure;
    {
        auto v = s.to_value(1);
        if (!v) {
            failure = std::move(v).error();
            failure->where = "rhp.emit";
        } else {
            try {
                impl_of(L).emit(*v);
            } catch (const std::exception& e) {
                failure = make_error(errc::kRuntime, e.what(), "rhp.emit");
            }
        }
    }
    if (failure) {
        s.raise(*failure);
    }
    return 0;
}

// rhp.off(id): removes a timer, frame callback or subscription, or cancels a task, the calling module made.
int lua_rhp_off(lua_State* L) {
    const stack s{L};
    const auto id = s.to_integer(1);
    if (!id || *id <= 0) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an id, got {}", s.type_name(1)), "rhp.off"));
    }
    impl_of(L).remove_by_id(L, static_cast<std::uint64_t>(*id));
    return 0;
}

// require(name): a read-only live proxy of a loaded module of this identity.
int lua_require(lua_State* L) {
    const stack s{L};
    const auto name = s.to_string(1);
    if (!name) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a module name, got {}", s.type_name(1)), "require"));
    }
    impl_of(L).push_required(L, *name);
    return 1;
}

// ---- require() proxies ---------------------------------------------------------------------------

// Userdata payload of a proxy; user value 1 is the module name (for messages after unload).
struct module_proxy {
    std::uint64_t id;
};

std::string proxy_name(lua_State* L, int index) {
    lua_getiuservalue(L, index, 1);
    std::size_t len = 0;
    const char* s = lua_tolstring(L, -1, &len);
    std::string name = s != nullptr ? std::string{s, len} : std::string{"?"};
    lua_pop(L, 1);
    return name;
}

int module_index(lua_State* L) {
    const auto* proxy = static_cast<const module_proxy*>(luaL_checkudata(L, 1, kModuleProxyKey));
    const module_record* mod = impl_of(L).record(module_id{proxy->id});
    if (mod == nullptr || mod->live.exports_ref == kNoRef) {
        stack{L}.raise(make_error(errc::kUnloaded, std::format("module '{}' was unloaded", proxy_name(L, 1))));
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
    lua_pushvalue(L, 2);
    lua_gettable(L, -2);
    return 1;
}

int module_newindex(lua_State* L) {
    (void)luaL_checkudata(L, 1, kModuleProxyKey);
    stack{L}.raise(make_error(errc::kInvalidArgument, std::format("module '{}' is read-only to require()rs", proxy_name(L, 1))));
}

int module_tostring(lua_State* L) {
    (void)luaL_checkudata(L, 1, kModuleProxyKey);
    const std::string name = proxy_name(L, 1);
    lua_pushfstring(L, "module: %s", name.c_str());
    return 1;
}

} // namespace

// ---- run scopes --------------------------------------------------------------------------------------

// One entry on the run stack: makes `owner` the running code and accounts its time to `budget`.
// The outermost scope clears a cancel() that arrived while nothing ran, and resets the hook after a
// stop switched it to every instruction.
struct sandbox_impl::active_scope {
    sandbox_impl& self;
    effect_owner previous;
    run_budget* previous_budget;

    active_scope(sandbox_impl& s, run_budget* budget, lua_State* thread, request_record* request, const effect_owner& owner)
        : self(s), previous(s.current_), previous_budget(s.budget_) {
        if (self.running_.empty()) {
            self.cancel_running_.store(false, std::memory_order_release);
        }
        const bool checked = request != nullptr && checked_kind(request->kind);
        if (self.metering_ && self.running_.empty()) {
            self.meter_run_started_ = steady::now();
        }
        self.running_.push_back(active_run{budget, thread, request, self.timed_ ? steady::now() : steady::time_point{}, checked});
        if (budget != nullptr) {
            self.budget_ = budget;
        }
        self.current_ = owner;
        if (checked) {
            self.enter_checked();
        }
    }

    active_scope(const active_scope&) = delete;
    active_scope& operator=(const active_scope&) = delete;

    ~active_scope() {
        const active_run& top = self.running_.back();
        if (top.budget != nullptr && self.timed_) {
            top.budget->active += steady::now() - top.started;
        }
        const bool checked = top.checked;
        self.running_.pop_back();
        self.budget_ = previous_budget;
        self.current_ = previous;
        if (self.metering_ && self.running_.empty()) {
            self.credit_hook_progress(self.state_);
            self.meter_active_ += steady::now() - self.meter_run_started_;
        }
        if (checked) {
            self.leave_checked();
        }
        if (self.running_.empty() && self.hook_dirty_) {
            self.hook_dirty_ = false;
            self.rearm_all(); // every coroutine, in case the profiler or the debugger changed the hook meanwhile
        }
    }
};

// limits.slice_us of wall time for everything started from here (an operation, pump(), an event).
struct sandbox_impl::slice_scope {
    sandbox_impl& self;
    bool owns;

    explicit slice_scope(sandbox_impl& s)
        : self(s), owns(s.options_.limits.slice_us != 0 && !s.slice_deadline_ && s.running_.empty()) {
        if (owns) {
            self.slice_deadline_ = steady::now() + std::chrono::microseconds{self.options_.limits.slice_us};
        }
    }

    slice_scope(const slice_scope&) = delete;
    slice_scope& operator=(const slice_scope&) = delete;

    ~slice_scope() {
        if (owns) {
            self.slice_deadline_.reset();
        }
    }
};

// An operation (exec, load, call, reload, unload, revert_all): while it runs, the main thread checks
// for cancel() too (on_save / on_restore / on_unload, and patch handlers its code hits), like its
// request coroutine does. Outside operations the main thread runs handlers, unchecked by default.
struct sandbox_impl::operation_scope {
    sandbox_impl& self;

    explicit operation_scope(sandbox_impl& s) : self(s) { self.enter_checked(); }

    operation_scope(const operation_scope&) = delete;
    operation_scope& operator=(const operation_scope&) = delete;

    ~operation_scope() { self.leave_checked(); }
};

// ---- construction --------------------------------------------------------------------------------

sandbox_impl::sandbox_impl(sandbox_options options)
    : options_(std::move(options)),
      memory_(options_.memory),
      small_(options_.memory),
      timed_(options_.limits.wall_ms != 0),
      thread_(std::this_thread::get_id()) {
    // Room for every spare up front: putting a finished request back never allocates (or throws).
    spare_requests_.reserve(kSpareRequests);
    spare_threads_.reserve(kSpareRequests);
    unlisted_.reserve(kSpareRequests); // runs nested deeper than this grow it (start_request may allocate anyway)
    state_ = lua_newstate(&sandbox_impl::allocate, this, luaL_makeseed(nullptr));
    if (state_ == nullptr) {
        throw std::bad_alloc{};
    }
    *static_cast<context**>(lua_getextraspace(state_)) = static_cast<context*>(this);
    lua_atpanic(state_, &on_panic);

    reset_hook();

    scratch_ = ids_.next();
    current_ = effect_owner{scratch_};
    auto opened = protect(state_, [this] {
        if (options_.gc != gc_mode::kIncremental) { // a new Lua 5.5 state starts incremental
            (void)lua_gc(state_, LUA_GCGEN);
            gc_mode_ = options_.gc;
        }
        open_libraries();
        open_stage7_libraries();
        module_record scratch;
        scratch.id = scratch_;
        scratch.name = "scratch";
        scratch.scratch = true;
        scratch.live.env_ref = new_environment();
        modules_.emplace(scratch_, std::move(scratch));
    });
    if (!opened) {
        lua_close(state_);
        state_ = nullptr;
        throw Rhp::exception{std::move(opened).error()};
    }
}

sandbox_impl::~sandbox_impl() {
    if (state_ == nullptr) {
        return;
    }
    closing_ = true;
    try {
        std::vector<module_id> ids;
        for (const auto& [id, mod] : modules_) {
            if (!mod.scratch) {
                ids.push_back(id);
            }
        }
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            if (module_record* mod = record(*it)) {
                (void)unload_module(*mod);
            }
        }
        abandon_requests([](const request_record&) { return true; }, "the sandbox was destroyed");
    } catch (...) { // a destructor must not throw; effects are still undone below
    }
    close_async();
    (void)ledger_.revert_all();
    closing_lua_ = true; // from here (lua_close runs finalizers) no effect is recorded, no event attached
    for (const auto& [name, state] : attached_) {
        state->detach(this);
    }
    attached_.clear();
    modules_.clear();
    lua_close(state_);
}

void sandbox_impl::open_libraries() {
    lua_State* L = state_;
    const bool admin = options_.caller_role == role::kAdmin;
    if (admin) {
        luaL_openselectedlibs(L, ~0, 0);
    } else {
        luaL_openselectedlibs(L, LUA_GLIBK | LUA_COLIBK | LUA_MATHLIBK | LUA_OSLIBK | LUA_STRLIBK | LUA_TABLIBK | LUA_UTF8LIBK, 0);
        for (const char* name : {"dofile", "loadfile", "collectgarbage"}) {
            lua_pushnil(L);
            lua_setglobal(L, name);
        }
        // string.dump would hand out binary chunks; os keeps only the clock.
        lua_getglobal(L, "string");
        lua_pushnil(L);
        lua_setfield(L, -2, "dump");
        lua_pop(L, 1);
        lua_getglobal(L, "os");
        lua_createtable(L, 0, 2);
        lua_getfield(L, -2, "time");
        lua_setfield(L, -2, "time");
        lua_getfield(L, -2, "clock");
        lua_setfield(L, -2, "clock");
        lua_setglobal(L, "os");
        lua_pop(L, 1);
    }

    // Binary chunks are never loaded, whatever the role: they are unverified and can crash the VM.
    lua_getglobal(L, "load");
    lua_pushcclosure(L, &lua_safe_load, 1);
    lua_setglobal(L, "load");

    lua_pushcfunction(L, &lua_print);
    lua_setglobal(L, "print");

    // require only finds loaded modules of this identity — never the file system, admin included.
    lua_pushcfunction(L, &lua_require);
    lua_setglobal(L, "require");

    // Request coroutines belong to the scheduler.
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushliteral(L, "k");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
    lua_setfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
    lua_getglobal(L, "coroutine");
    for (const char* name : {"resume", "close"}) {
        lua_getfield(L, -1, name);
        lua_pushcclosure(L, &lua_guarded_coroutine, 1);
        lua_setfield(L, -2, name);
    }
    lua_pushcfunction(L, &lua_coroutine_wrap);
    lua_setfield(L, -2, "wrap");
    lua_pop(L, 1);

    struct builtin {
        const char* name;
        lua_CFunction fn;
    };
    constexpr builtin builtins[] = {
        {"patch", &lua_rhp_patch},
        {"wait", &lua_rhp_wait},
        {"next_frame", &lua_rhp_next_frame},
        {"sleep", &lua_rhp_sleep},
        {"frame", &lua_rhp_frame},
        {"emit", &lua_rhp_emit},
        {"timer", &lua_rhp_timer},
        {"after", &lua_rhp_after},
        {"every", &lua_rhp_every},
        {"every_frame", &lua_rhp_every_frame},
        {"every_frames", &lua_rhp_every_frames},
        {"pause", &lua_rhp_pause},
        {"resume", &lua_rhp_resume},
        {"reschedule", &lua_rhp_reschedule},
        {"timers", &lua_rhp_timers},
        {"on", &lua_rhp_on},
        {"once", &lua_rhp_once},
        {"on_error", &lua_rhp_on_error},
        {"off", &lua_rhp_off},
        {"publish", &lua_rhp_publish},
        {"wait_event", &lua_rhp_wait_event},
        {"stats", &lua_rhp_stats},
        {"spawn", &lua_rhp_spawn},
        {"tasks", &lua_rhp_tasks},
        {"tunables", &lua_rhp_tunables},
        {"api", &lua_rhp_api},
    };
    lua_createtable(L, 0, static_cast<int>(std::size(builtins)) + 1);
    for (const auto& [name, fn] : builtins) {
        lua_pushcfunction(L, fn);
        lua_setfield(L, -2, name);
    }
    stack{L}.push_string(to_string(options_.caller_role));
    lua_setfield(L, -2, "role");
    lua_setglobal(L, "rhp");

    // The token behind `original` in patch handlers.
    const std::string original_key{kOriginalTokenKey};
    luaL_newmetatable(L, original_key.c_str());
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);

    // require() proxies, one per module (cached so require("x") == require("x")).
    luaL_newmetatable(L, kModuleProxyKey);
    lua_pushcfunction(L, &module_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, &module_newindex);
    lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, &module_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushliteral(L, "module");
    lua_setfield(L, -2, "__name");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kModuleProxiesKey);

    // The module loader, compiled once against the base globals.
    if (luaL_loadbufferx(L, kLoaderSource.data(), kLoaderSource.size(), "=rhp.loader", "t") != LUA_OK) {
        lua_error(L);
    }
    lua_call(L, 0, 1);
    loader_ref_ = luaL_ref(L, LUA_REGISTRYINDEX);
}

// A module's _ENV: its own globals, reading through to the shared base (stdlib + libs + rhp).
// _G is the module's own environment, so `_G.x = 1` stays inside the module.
int sandbox_impl::new_environment() {
    lua_State* L = state_;
    lua_createtable(L, 0, 4);
    lua_createtable(L, 0, 2);
    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_setmetatable(L, -2);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
    return luaL_ref(L, LUA_REGISTRYINDEX);
}

// ---- allocator and hook ----------------------------------------------------------------------------

std::uint32_t sandbox_impl::check_interval() const noexcept {
    return options_.limits.cancel_check_instructions != 0 ? options_.limits.cancel_check_instructions : kDefaultCheckInterval;
}

bool sandbox_impl::hook_everywhere() const noexcept {
    const Rhp::limits& l = options_.limits;
    return l.instructions != 0 || l.wall_ms != 0 || l.slice_us != 0 || l.cancel_checks == cancel_scope::kEverything;
}

std::uint32_t sandbox_impl::hook_count() const noexcept {
    return profiler_ ? std::min(check_interval(), profiler_->options.interval) : check_interval();
}

// `armed`: the run checks for cancels and limits. The profiler counts everywhere; the debugger adds
// line events.
void sandbox_impl::arm_hook(lua_State* L, bool armed) noexcept {
    credit_hook_progress(L); // lua_sethook restarts the countdown: the meter keeps what ran of it
    // Line events: every line, or by function (internals::set_line_events switches them without
    // restarting the instruction countdown, so limits and cancels keep working in loops of calls).
    const int mask = (armed || counts_everywhere() ? LUA_MASKCOUNT : 0) | line_mask();
    install_hook(L, mask, static_cast<int>(hook_count()));
}

// Cancels and limits only need a bound, so a hook that does nothing else counts at safe points (loop
// back-edges and calls: internals::set_safepoint_hook) and costs nothing in straight-line code. The
// meter, the profiler and line events need every instruction: lua_sethook.
bool sandbox_impl::counts_at_safepoints(int mask) const noexcept {
    return mask == LUA_MASKCOUNT && !counts_everywhere();
}

void sandbox_impl::install_hook(lua_State* L, int mask, int count) noexcept {
    if (mask == 0) {
        lua_sethook(L, nullptr, 0, 0);
    } else if (counts_at_safepoints(mask)) {
        internals::set_safepoint_hook(L, &sandbox_impl::count_hook, count);
    } else {
        lua_sethook(L, &sandbox_impl::count_hook, mask, count);
    }
}

void sandbox_impl::rearm_all() noexcept {
    if (hook_dirty_) {
        return; // a stop fires on every instruction until the outermost run ends; that rearms
    }
    reset_hook();
    for (const auto& [id, req] : requests_) {
        if (req->thread != nullptr) {
            arm_hook(req->thread, hook_everywhere() || req->checked);
        }
    }
}

bool sandbox_impl::checked_now() const noexcept {
    if (hook_everywhere()) {
        return true;
    }
    if (!checks_requests()) {
        return false;
    }
    if (checked_depth_ != 0) {
        return true;
    }
    const active_run& top = running_.back();
    return top.request != nullptr && top.request->checked;
}

void sandbox_impl::sync_hook(lua_State* L, bool checked) noexcept {
    const int mask = (checked || counts_everywhere() ? LUA_MASKCOUNT : 0) | line_mask();
    const int count = static_cast<int>(hook_count());
    // By function, a thread's line events come and go with its calls: either is in step.
    const int ignored = lines_wanted() == line_mode::kByFunction ? LUA_MASKLINE : 0;
    const bool at_safepoints = internals::hook_at_safepoints(L);
    const int current = at_safepoints ? LUA_MASKCOUNT : lua_gethookmask(L);
    if ((current | ignored) == mask && at_safepoints == counts_at_safepoints(mask) && ((mask & LUA_MASKCOUNT) == 0 || lua_gethookcount(L) == count)) {
        return;
    }
    credit_hook_progress(L);
    install_hook(L, mask, count);
}

bool sandbox_impl::checks_requests() const noexcept {
    return options_.limits.cancel_checks != cancel_scope::kNone;
}

void sandbox_impl::reset_hook() noexcept {
    arm_hook(state_, hook_everywhere() || (checked_depth_ != 0 && checks_requests()));
}

// A stop already switched the hook to every instruction (hook_dirty_): leave it, the outermost run
// resets it when it ends.
void sandbox_impl::enter_checked() noexcept {
    if (checked_depth_++ == 0 && checks_requests() && !hook_everywhere() && !hook_dirty_) {
        arm_hook(state_, true);
    }
}

void sandbox_impl::leave_checked() noexcept {
    if (--checked_depth_ == 0 && checks_requests() && !hook_everywhere() && !hook_dirty_) {
        arm_hook(state_, false);
    }
}

void sandbox_impl::free_block(void* block, std::size_t size) noexcept {
    if (small_alloc::fits(size)) {
        small_.deallocate(block);
    } else if (memory_ == nullptr) {
        std::free(block);
    } else {
        memory_->deallocate(block, size, kAlignment);
    }
}

void* sandbox_impl::heap_allocate(std::size_t size) noexcept {
    if (memory_ == nullptr) {
        return std::malloc(size);
    }
    try {
        return memory_->allocate(size, kAlignment);
    } catch (...) {
        return nullptr;
    }
}

void* sandbox_impl::allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept {
    auto& self = *static_cast<sandbox_impl*>(ud);
    const std::size_t old_tag = old_size;
    if (ptr == nullptr) {
        old_size = 0; // Lua passes the object type here for new blocks
    }
    if (new_size == 0) {
        if (ptr != nullptr) {
            self.free_block(ptr, old_size);
            self.memory_used_ -= old_size;
            ++self.frees_;
        }
        return nullptr;
    }
    const std::size_t kind = ptr == nullptr ? alloc_kind_of(old_tag) : kAllocKinds;
    if (new_size > old_size) {
        const std::uint64_t limit = self.options_.limits.memory;
        run_budget* const budget = self.budget_; // innermost run with its own budget
        if (budget != nullptr && budget->sticky == sticky_stop::kMemory) {
            return nullptr;
        }
        if (limit != 0 && self.memory_used_ - old_size + new_size > limit) {
            if (budget != nullptr && budget->sticky == sticky_stop::kNone) {
                budget->sticky = sticky_stop::kMemory;
            }
            return nullptr;
        }
    }
    // Where a block lives follows from its size alone (Lua passes it back on every call): up to
    // small_alloc::kMaxSize in the small-object slabs, larger ones on the C heap or memory_.
    void* block = nullptr;
    const bool was_small = ptr != nullptr && small_alloc::fits(old_size);
    if (small_alloc::fits(new_size)) {
        if (was_small && (new_size < old_size || small_alloc::same_class(old_size, new_size))) {
            // Stays where it is: the same class, or smaller (a slab block is freed by its address,
            // whatever size it is freed as, so shrinking in place never fails).
            if (!small_alloc::same_class(old_size, new_size)) {
                if (void* moved = self.small_.allocate(new_size)) { // a smaller class when there is room
                    std::memcpy(moved, ptr, new_size);
                    self.small_.deallocate(ptr);
                    ptr = moved;
                }
            }
            block = ptr;
        } else {
            block = self.small_.allocate(new_size);
            if (block == nullptr) {
                return nullptr; // `ptr` is untouched
            }
            if (ptr != nullptr) {
                std::memcpy(block, ptr, std::min(old_size, new_size));
                self.free_block(ptr, old_size);
            }
        }
    } else if (was_small) {
        block = self.heap_allocate(new_size);
        if (block == nullptr) {
            return nullptr;
        }
        std::memcpy(block, ptr, old_size);
        self.small_.deallocate(ptr);
    } else if (self.memory_ == nullptr) {
        // The C heap, like Lua's own allocator: a block grows or shrinks in place when it can.
        block = std::realloc(ptr, new_size);
        if (block == nullptr) {
            return nullptr; // `ptr` is untouched
        }
    } else {
        block = self.heap_allocate(new_size);
        if (block == nullptr) {
            return nullptr;
        }
        if (ptr != nullptr) {
            std::memcpy(block, ptr, std::min(old_size, new_size));
            self.memory_->deallocate(ptr, old_size, kAlignment);
        }
    }
    self.memory_used_ = self.memory_used_ - old_size + new_size;
    if (new_size > old_size) {
        self.bytes_allocated_ += new_size - old_size;
        self.peak_ = std::max(self.peak_, self.memory_used_);
    }
    if (kind != kAllocKinds) {
        ++self.allocations_;
        ++self.objects_[kind];
    }
    return block;
}

void sandbox_impl::check_cancels() noexcept {
    if (cancel_running_.exchange(false, std::memory_order_acq_rel)) {
        for (active_run& run : running_) {
            if (run.budget != nullptr && run.budget->sticky == sticky_stop::kNone) {
                run.budget->sticky = sticky_stop::kCancelled;
            }
        }
    }
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return;
    }
    const std::scoped_lock lock{inbox_mutex_};
    // Running requests stop here; suspended ones are ended before they resume (take_cancel) or by
    // the next drain(), so their ids stay pending.
    std::erase_if(cancel_ids_, [this](request_id id) {
        for (active_run& run : running_) {
            if (run.request != nullptr && run.request->id == id) {
                if (run.budget->sticky == sticky_stop::kNone) {
                    run.budget->sticky = sticky_stop::kCancelled;
                }
                return true;
            }
        }
        return false;
    });
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
}

bool sandbox_impl::take_cancel(request_id id) {
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return false;
    }
    const std::scoped_lock lock{inbox_mutex_};
    const auto it = std::ranges::find(cancel_ids_, id);
    if (it == cancel_ids_.end()) {
        return false;
    }
    cancel_ids_.erase(it);
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
    return true;
}

void sandbox_impl::count_hook(lua_State* L, lua_Debug* ar) {
    auto& self = impl_of(L);
    if (ar->event == LUA_HOOKLINE) {
        self.line_event(L, ar);
        return;
    }
    if (ar->event == LUA_HOOKCALL || ar->event == LUA_HOOKTAILCALL || ar->event == LUA_HOOKRET) {
        self.scope_lines(L, ar);
        return;
    }
    if (self.running_.empty()) {
        return; // a handler called from game code runs inside run_handler, so this is GC / setup code
    }
    // The instructions since this thread's last count event: its own count, which may be older than
    // hook_count() (a thread armed before the profiler started or stopped).
    const auto elapsed = static_cast<std::uint64_t>(lua_gethookcount(L));
    if (self.metering_) {
        self.meter_instructions_ += elapsed;
    }
    if (!self.hook_dirty_) { // after a stop the hook fires on every instruction until the run ends
        const bool checked = self.checked_now();
        if (self.profiler_) {
            self.profile_tick(L, elapsed);
        }
        self.sync_hook(L, checked);
        if (!checked) {
            return; // armed for the profiler only, or a thread whose hook was out of date
        }
    }
    self.check_cancels();
    const auto& limits = self.options_.limits;
    const bool timed = limits.wall_ms != 0 || self.slice_deadline_.has_value();
    const steady::time_point now = timed ? steady::now() : steady::time_point{};
    sticky_stop stop = sticky_stop::kNone;
    for (active_run& run : self.running_) {
        if (run.budget == nullptr) {
            continue;
        }
        run_budget& budget = *run.budget;
        if (budget.sticky == sticky_stop::kNone) {
            if (limits.instructions != 0 && (budget.instructions += elapsed) > limits.instructions) {
                budget.sticky = sticky_stop::kBudget;
            } else if (limits.wall_ms != 0 && budget.active + (now - run.started) > std::chrono::milliseconds{limits.wall_ms}) {
                budget.sticky = sticky_stop::kWall;
            }
        }
        if (budget.sticky != sticky_stop::kNone) {
            stop = budget.sticky; // the innermost stopped run decides the error
        }
    }
    if (stop != sticky_stop::kNone) {
        // From now on fire on every instruction (this thread and the main one), so a script that keeps
        // re-entering pcall can't swallow the stop between two widely spaced hook ticks.
        self.hook_dirty_ = true;
        lua_sethook(L, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        lua_sethook(self.state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        stack{L}.raise(self.sticky_error(stop));
    }
    // End of the time slice: yield the request's own thread (never a coroutine it created, never
    // across a C call); it continues at the next pump().
    if (self.slice_deadline_ && now >= *self.slice_deadline_) {
        const active_run& top = self.running_.back();
        if (top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0) {
            top.request->sliced = true;
            (void)lua_yield(L, 0);
        }
    }
}

error sandbox_impl::sticky_error(sticky_stop stop) const {
    const auto& limits = options_.limits;
    switch (stop) {
    case sticky_stop::kCancelled: return make_error(errc::kCancelled, "script cancelled");
    case sticky_stop::kBudget: return make_error(errc::kBudgetExceeded, std::format("instruction limit of {} exceeded", limits.instructions));
    case sticky_stop::kMemory: return make_error(errc::kMemoryExceeded, std::format("memory limit of {} bytes exceeded", limits.memory));
    case sticky_stop::kWall: return make_error(errc::kTimeout, std::format("wall time limit of {} ms exceeded", limits.wall_ms));
    case sticky_stop::kNone: break;
    }
    return make_error(errc::kRuntime);
}

// ---- context -------------------------------------------------------------------------------------

std::uint64_t sandbox_impl::record_effect(std::string label, std::unique_ptr<effect> e) {
    if (closing_lua_) {
        // A finalizer run by lua_close: the ledger is already empty and must stay so; undo at once.
        try {
            e->undo();
        } catch (...) { // an undo that fails while the sandbox closes has nobody to report to
        }
        return 0;
    }
    effect_owner owner = current_;
    if (record(owner.module) == nullptr) {
        owner = effect_owner{scratch_};
    }
    return ledger_.record(owner, std::move(label), std::move(e));
}

result<void> sandbox_impl::run_handler(const effect_owner& owner, c_function fn, void* data) {
    // Inside a running script the handler is part of that run; from game code it is a run of its own.
    run_budget local;
    run_budget* budget = running_.empty() ? &local : nullptr;
    result<void> ran;
    {
        const active_scope scope{*this, budget, nullptr, nullptr, owner};
        ran = stack{state_}.run_protected(fn, data);
    }
    if (budget != nullptr && local.sticky != sticky_stop::kNone) {
        error stop = sticky_error(local.sticky);
        if (ran) {
            return std::unexpected{std::move(stop)};
        }
        ran.error().code = stop.code;
    }
    return ran;
}

void sandbox_impl::report_fault(const effect_owner& owner, error err) noexcept {
    // A stop of the run around the handler (cancel, a limit) is that run's failure, not the handler's.
    for (const active_run& run : running_) {
        if (run.budget != nullptr && run.budget->sticky != sticky_stop::kNone) {
            return;
        }
    }
    try {
        pending_faults_.emplace_back(owner, std::move(err));
    } catch (...) { // out of memory: the fault is dropped, the patch keeps falling back
    }
}

void sandbox_impl::output_line(std::string_view line) {
    if (options_.on_output) {
        options_.on_output(current_.request, current_.module, line);
    } else if (options_.output) {
        options_.output(line);
    } else {
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
    }
}

void sandbox_impl::emit(const value& v) {
    if (options_.on_emit) {
        options_.on_emit(current_.request, current_.module, v);
    }
}

module_record* sandbox_impl::record(module_id mod) noexcept {
    const auto it = modules_.find(mod);
    return it != modules_.end() ? &it->second : nullptr;
}

const module_record* sandbox_impl::record(module_id mod) const noexcept {
    const auto it = modules_.find(mod);
    return it != modules_.end() ? &it->second : nullptr;
}

module_instance* sandbox_impl::instance_of(module_record& mod, revision_id revision) noexcept {
    if (mod.pending && mod.pending->revision == revision) {
        return &*mod.pending;
    }
    return mod.live.revision == revision ? &mod.live : nullptr;
}

int sandbox_impl::current_env() const noexcept {
    const module_record* mod = record(current_.module);
    if (mod == nullptr) {
        mod = record(scratch_);
    }
    if (mod->pending && mod->pending->revision == current_.revision) {
        return mod->pending->env_ref;
    }
    return mod->live.env_ref;
}

steady::time_point sandbox_impl::script_now() const {
    return options_.clock ? options_.clock() : steady::now();
}

request_record& sandbox_impl::suspendable(lua_State* L, std::string_view what) {
    if (!running_.empty()) {
        const active_run& top = running_.back();
        if (top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0) {
            return *top.request;
        }
    }
    stack{L}.raise(make_error(errc::kInvalidArgument,
                              "only a script's own thread can suspend (not a patch handler, on_save / on_restore / on_unload, "
                              "a coroutine it created, or a callback of a C function such as table.sort)",
                              std::string{what}));
}

// ---- ids the scripts hold --------------------------------------------------------------------------

bool sandbox_impl::owns_entry(std::uint64_t seq) const noexcept {
    const ledger::entry* entry = ledger_.find(seq);
    return entry != nullptr && entry->owner == current_.module;
}

request_record* sandbox_impl::running_request() noexcept {
    for (auto it = running_.rbegin(); it != running_.rend(); ++it) {
        if (it->request != nullptr) {
            return it->request;
        }
    }
    return nullptr;
}

void sandbox_impl::remove_by_id(lua_State* L, std::uint64_t seq) {
    bool known = false;
    if (owns_entry(seq)) {
        const task_record* t = task_by_seq(seq);
        known = schedule_by_seq(seq) != nullptr || subscription_by_seq(seq) != nullptr || (t != nullptr && !t->finished);
    }
    if (!known) {
        stack{L}.raise(make_error(errc::kNotFound, std::format("no timer, frame callback, subscription or task {} of this module", seq), "rhp.off"));
    }
    (void)ledger_.revert_entry(seq);
}

// ---- events ------------------------------------------------------------------------------------------

void sandbox_impl::deliver(std::string_view event, const event_args& args) {
    (void)protect(state_, [&] {
        const slice_scope slice{*this};
        deliver_now(event, event_pusher{args.data, args.push}, module_id{}, nullptr);
    });
    if (running_.empty()) {
        report_failures(); // a fire from game code: no operation or pump() ends after it
    }
}

// ---- require -------------------------------------------------------------------------------------------

bool sandbox_impl::depends_on(module_id from, module_id to, std::vector<module_id>& path) const {
    path.push_back(from);
    if (from == to) {
        return true;
    }
    if (const module_record* mod = record(from)) {
        const auto visit = [&](const std::set<module_id>& deps) {
            return std::ranges::any_of(deps, [&](module_id dep) { return std::ranges::find(path, dep) == path.end() && depends_on(dep, to, path); });
        };
        if (visit(mod->live.dependencies) || (mod->pending && visit(mod->pending->dependencies))) {
            return true;
        }
    }
    path.pop_back();
    return false;
}

void sandbox_impl::push_required(lua_State* L, std::string_view name) {
    const stack s{L};
    module_record* target = nullptr;
    for (auto& [id, mod] : modules_) {
        if (!mod.scratch && mod.name == name) {
            target = &mod;
        }
    }
    if (target == nullptr) {
        s.raise(make_error(errc::kNotFound, std::format("module '{}' is not loaded (require only finds loaded modules of this identity)", name), "require"));
    }
    if (target->id == current_.module) {
        s.raise(make_error(errc::kInvalidArgument, std::format("module '{}' can't require itself", name), "require"));
    }
    if (target->live.exports_ref == kNoRef) {
        const std::string why = target->state == module_state::kLoading ? "is still loading" : std::format("has no exports (it is {})", target->state);
        s.raise(make_error(errc::kInvalidArgument, std::format("module '{}' {}", name, why), "require"));
    }
    if (module_record* self = record(current_.module); self != nullptr && !self->scratch) {
        if (module_instance* instance = instance_of(*self, current_.revision); instance != nullptr && !instance->dependencies.contains(target->id)) {
            std::vector<module_id> path;
            if (depends_on(target->id, self->id, path)) {
                std::string chain = self->name;
                for (const module_id id : path) {
                    const module_record* step = record(id);
                    chain += std::format(" -> {}", step != nullptr ? step->name : "?");
                }
                s.raise(make_error(errc::kInvalidArgument, std::format("require cycle: {}", chain), "require"));
            }
            instance->dependencies.insert(target->id);
        }
    }

    const auto key = static_cast<lua_Integer>(target->id.value());
    lua_getfield(L, LUA_REGISTRYINDEX, kModuleProxiesKey);
    if (lua_rawgeti(L, -1, key) == LUA_TUSERDATA) {
        lua_remove(L, -2);
        return;
    }
    lua_pop(L, 1);
    auto* proxy = static_cast<module_proxy*>(lua_newuserdatauv(L, sizeof(module_proxy), 1));
    proxy->id = target->id.value();
    s.push_string(target->name);
    lua_setiuservalue(L, -2, 1);
    luaL_setmetatable(L, kModuleProxyKey);
    lua_pushvalue(L, -1);
    lua_rawseti(L, -3, key);
    lua_remove(L, -2);
}

const module_record* sandbox_impl::module_of_proxy(lua_State* L, int index) const noexcept {
    const auto* proxy = static_cast<const module_proxy*>(luaL_testudata(L, index, kModuleProxyKey));
    return proxy != nullptr ? record(module_id{proxy->id}) : nullptr;
}

void sandbox_impl::forget_proxy(module_id mod) noexcept {
    lua_getfield(state_, LUA_REGISTRYINDEX, kModuleProxiesKey);
    lua_pushnil(state_);
    lua_rawseti(state_, -2, static_cast<lua_Integer>(mod.value()));
    lua_pop(state_, 1);
}

std::vector<std::string> sandbox_impl::dependents_of(module_id mod) const {
    std::vector<std::string> out;
    for (const auto& [id, other] : modules_) {
        if (id != mod && (other.live.dependencies.contains(mod) || (other.pending && other.pending->dependencies.contains(mod)))) {
            out.push_back(other.name);
        }
    }
    return out;
}

// ---- requests --------------------------------------------------------------------------------------

namespace {

// Bytecode of trusted chunks (the test framework), compiled once per process: a sandbox per test
// file would otherwise parse the same 100 KB of Lua every time. Keyed by chunk name and source; the
// bytecode keeps its debug information (lines for errors and coverage).
class bytecode_cache {
public:
    // The bytecode of (name, source), or empty when it isn't cached yet.
    std::string find(std::string_view name, std::string_view source) {
        const std::scoped_lock lock{mutex_};
        const auto it = cache_.find(key(name, source));
        return it != cache_.end() ? it->second : std::string{};
    }

    void store(std::string_view name, std::string_view source, std::string bytecode) {
        const std::scoped_lock lock{mutex_};
        // Bounded: a long-lived process running edited sources again and again starts over.
        bytes_ += name.size() + source.size() + bytecode.size();
        if (bytes_ > kMaxBytes) {
            cache_.clear();
            bytes_ = name.size() + source.size() + bytecode.size();
        }
        cache_.insert_or_assign(key(name, source), std::move(bytecode));
    }

private:
    static std::string key(std::string_view name, std::string_view source) {
        std::string k;
        k.reserve(name.size() + 1 + source.size());
        k.append(name).push_back('\0');
        k.append(source);
        return k;
    }

    static constexpr std::size_t kMaxBytes = 64u * 1024u * 1024u;

    std::mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
    std::size_t bytes_ = 0;
};

bytecode_cache& exec_bytecode() {
    static bytecode_cache cache;
    return cache;
}

int dump_writer(lua_State*, const void* p, size_t size, void* out) {
    if (p != nullptr) {
        static_cast<std::string*>(out)->append(static_cast<const char*>(p), size);
    }
    return 0;
}

// Pushes the function of trusted bytecode compiled as `chunk_name`; false (nothing pushed) when Lua
// refuses it (another Lua build, truncated, text) or it isn't a main chunk compiled under that name
// (one upvalue, _ENV; vararg; no parameters).
bool load_bytecode(lua_State* L, std::string_view bytecode, const std::string& chunk_name) {
    if (luaL_loadbufferx(L, bytecode.data(), bytecode.size(), chunk_name.c_str(), "b") != LUA_OK) {
        lua_pop(L, 1); // the error
        return false;
    }
    lua_Debug ar{};
    lua_pushvalue(L, -1);
    lua_getinfo(L, ">Su", &ar);
    if (ar.source == nullptr || std::string_view{ar.source, ar.srclen} != chunk_name || ar.nups != 1 || ar.nparams != 0 || ar.isvararg == 0) {
        lua_pop(L, 1);
        return false;
    }
    return true;
}

// A chunk exercising what bytecode encodes (integers, floats, strings, nested functions, upvalues,
// varargs, gotos, line info): its dump changes when the compiler or the dump format does.
constexpr std::string_view kProbeChunk = R"lua(local a, b, c = 1, 2.5, "probe"
local t = {a, b, c, x = -0.0, [3] = 0x7fffffffffffffff, 1e308, [[long
string]]}
local function f(n, ...)
    local s = 0
    for i = 1, n do
        s = s + i // 2 % 3
    end
    goto done
    ::done::
    return function(...) return s, t, select("#", ...), ... end
end
return f(10, a, b, c)
)lua";

// lua_pcall'd: compiles the probe chunk and dumps it into the std::string argument 1 points to.
int dump_probe(lua_State* L) {
    auto* out = static_cast<std::string*>(lua_touserdata(L, 1));
    if (luaL_loadbufferx(L, kProbeChunk.data(), kProbeChunk.size(), "=rhp.bytecode_build", "t") != LUA_OK) {
        return lua_error(L);
    }
    lua_dump(L, &dump_writer, out, 0);
    return 0;
}

std::string make_bytecode_build() {
    lua_State* L = luaL_newstate();
    if (L == nullptr) {
        return {};
    }
    std::string dumped;
    bool made = false;
    try {
        lua_pushcfunction(L, &dump_probe);
        lua_pushlightuserdata(L, &dumped);
        made = lua_pcall(L, 1, 0, 0) == LUA_OK && !dumped.empty();
    } catch (const std::exception&) { // out of memory while dumping
        made = false;
    }
    lua_close(L);
    return made ? std::format("rhp bytecode build: lua {}\n", LUA_VERSION_RELEASE_NUM) + dumped : std::string{};
}

} // namespace

result<void> sandbox_impl::compile(std::string_view source, const std::string& chunk_name, int env_ref, bool cached, std::string_view trusted) {
    lua_State* L = state_;
    bool from_trusted = false;
    if (!trusted.empty()) {
        from_trusted = load_bytecode(L, trusted, chunk_name);
        ++(from_trusted ? bytecode_loaded_ : bytecode_rejected_);
    }
    if (!from_trusted) {
        std::string bytecode = cached ? exec_bytecode().find(chunk_name, source) : std::string{};
        const int status = bytecode.empty() ? luaL_loadbufferx(L, source.data(), source.size(), chunk_name.c_str(), "t")
                                            : luaL_loadbufferx(L, bytecode.data(), bytecode.size(), chunk_name.c_str(), "b");
        if (status == LUA_OK && cached && bytecode.empty()) {
            std::string dumped;
            if (lua_dump(L, &dump_writer, &dumped, 0) == 0 && !dumped.empty()) {
                exec_bytecode().store(chunk_name, source, std::move(dumped));
            }
        }
        if (status != LUA_OK) {
            error err = take_lua_error(L, status);
            if (err.code == errc::kRuntime) {
                err.code = errc::kCompile;
            }
            return std::unexpected{std::move(err)};
        }
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, env_ref);
    lua_setupvalue(L, -2, 1); // a main chunk's first upvalue is _ENV
    if (coverage_) {
        coverage_compiled(L, std::string_view{chunk_name}.substr(1));
    }
    return {};
}

template <class Pred>
void sandbox_impl::abandon_requests(Pred pred, std::string_view why) {
    std::vector<request_id> doomed;
    for (const auto& [id, req] : requests_) {
        if (!req->running && pred(*req)) {
            doomed.push_back(id);
        }
    }
    for (const request_id id : doomed) {
        auto node = requests_.extract(id);
        if (node.empty()) {
            continue;
        }
        request_record& req = *node.mapped();
        req.listed = false;
        const result<value_list> outcome = fail(errc::kCancelled, std::string{why}, where_of(req));
        close_thread(req, true);
        request_ended(req, &outcome, true);
        if (req.suspended_once) {
            finished_.emplace_back(id, outcome);
        }
        if (spare_requests_.size() < kSpareRequests) {
            spare_requests_.push_back(std::move(node)); // reserved in the constructor: no allocation
        }
    }
}

void sandbox_impl::abandon_request(request_id id, std::string_view why) {
    abandon_requests([id](const request_record& r) { return r.id == id; }, why);
}

request_record& sandbox_impl::start_request(request_kind kind, const effect_owner& owner, std::string_view label, int nargs, bool from_operation) {
    lua_State* L = state_;
    const request_id id = request_ids_.next();
    // A finished request's map node and record when one is spare, else new ones (made in the map and
    // taken out again: every record lives in a node, listed or not).
    decltype(requests_)::node_type node;
    if (!spare_requests_.empty()) {
        node = std::move(spare_requests_.back());
        spare_requests_.pop_back();
        node.mapped()->reset();
    } else {
        node = requests_.extract(requests_.emplace(id, std::make_unique<request_record>()).first);
    }
    request_record& req = *node.mapped();
    req.label.assign(label);

    luaL_checkstack(L, 5, "rhp: request setup"); // every caller runs protected on the main state (spawn checked it)
    lua_State* co = nullptr;
    if (!spare_threads_.empty()) {
        std::tie(co, req.thread_ref) = spare_threads_.back();
        spare_threads_.pop_back();
    } else {
        co = lua_newthread(L);
        lua_getfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
        lua_pushvalue(L, -2);
        lua_pushboolean(L, 1);
        lua_rawset(L, -3);
        lua_pop(L, 1);
        req.thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    try {
        prepare_request(req, co, kind, owner, id, nargs);
        node.key() = id;
        if (kind == request_kind::kTask) {
            // A task starts at a later pump(): the scheduler must see it now.
            req.listed = true;
            requests_.insert(std::move(node)); // reuses the node: no allocation
            requests_dirty_ = true;
        } else {
            unlisted_.push_back(std::move(node)); // reserved in the constructor (deeper nesting grows it)
        }
    } catch (...) { // out of memory part way: the coroutine is emptied and kept (the pool has room: it was just taken from, or reserved)
        lua_settop(co, 0);
        if (spare_threads_.size() < spare_threads_.capacity()) {
            spare_threads_.emplace_back(co, req.thread_ref);
        } else {
            luaL_unref(L, LUA_REGISTRYINDEX, req.thread_ref);
        }
        throw;
    }

    if (from_operation) {
        last_request_ = id;
    }
    return req;
}

void sandbox_impl::prepare_request(request_record& req, lua_State* co, request_kind kind, const effect_owner& owner, request_id id, int nargs) {
    req.id = id;
    req.kind = kind;
    req.owner = owner;
    req.owner.request = id;
    // Requests check for cancel() (handlers only when a limit or cancel_scope::kEverything asks).
    // A handler started while a checked run is active is part of that run's work (an event fired
    // synchronously by its code): it checks too.
    req.checked = checks_requests() && (checked_kind(kind) || checked_depth_ != 0);
    arm_hook(co, hook_everywhere() || req.checked);
    // lua_xmove never grows the destination: a new coroutine has room for about 20 values.
    if (lua_checkstack(co, nargs + 1) == 0) {
        req.start_error = make_error(errc::kLimitExceeded, std::format("{} arguments don't fit a coroutine stack", nargs));
    }
    req.thread = co;
    if (req.start_error) {
        lua_pop(state_, nargs + 1); // the request ends at its first step
    } else {
        lua_xmove(state_, co, nargs + 1); // the function and its arguments
    }
}

request_record& sandbox_impl::restart_request(request_record& req, request_kind kind, const effect_owner& owner, int nargs) {
    lua_State* co = req.thread;
    const int ref = req.thread_ref;
    req.reset();
    req.thread = co; // release_kept still finds the coroutine if the rest throws
    req.thread_ref = ref;
    prepare_request(req, co, kind, owner, request_ids_.next(), nargs);
    return req;
}

void sandbox_impl::release_kept(request_record& req) noexcept {
    auto node = take_unlisted(req); // compares addresses only: `req` may be a record already recycled
    if (node.empty()) {
        return;
    }
    if (req.thread != nullptr) {
        close_thread(req, false);
    }
    if (spare_requests_.size() < kSpareRequests) {
        spare_requests_.push_back(std::move(node)); // reserved in the constructor: no allocation
    }
}

std::map<request_id, std::unique_ptr<request_record>>::node_type sandbox_impl::take_unlisted(const request_record& req) noexcept {
    for (auto it = unlisted_.end(); it != unlisted_.begin();) {
        --it;
        if (it->mapped().get() == &req) {
            auto node = std::move(*it);
            unlisted_.erase(it);
            return node;
        }
    }
    return {};
}

void sandbox_impl::list_request(request_record& req) noexcept {
    requests_dirty_ = true; // suspended with a new wake
    if (req.listed) {
        return;
    }
    auto node = take_unlisted(req);
    if (node.empty()) {
        return;
    }
    node.key() = req.id;
    requests_.insert(std::move(node)); // reuses the node: no allocation
    req.listed = true;
    // A profiler or debugger that started while it ran re-armed the listed coroutines only (rearm_all).
    if (!hook_dirty_) {
        sync_hook(req.thread, hook_everywhere() || req.checked);
    }
}

bool sandbox_impl::live(request_id request) const noexcept {
    if (requests_.contains(request)) {
        return true;
    }
    return std::ranges::any_of(running_, [request](const active_run& run) { return run.request != nullptr && run.request->id == request; });
}

std::string sandbox_impl::where_of(const request_record& req) const {
    if (!req.label.empty()) {
        return req.label;
    }
    const module_record* mod = record(req.owner.module);
    const std::string_view name = mod != nullptr ? std::string_view{mod->name} : std::string_view{"?"};
    switch (req.kind) {
    case request_kind::kFrame: return std::format("{} (frame callback)", name);
    case request_kind::kTimer: return std::format("{} (timer)", name);
    case request_kind::kEvent: return std::format("{} (event {})", name, req.source);
    case request_kind::kTask: return std::format("{} (task)", mod != nullptr && !mod->scratch ? name : std::string_view{"exec"});
    case request_kind::kExec:
    case request_kind::kLoad:
    case request_kind::kCall: break;
    }
    return {};
}

std::optional<result<value_list>> sandbox_impl::step(request_record& req, int nargs, bool* kept) {
    if (kept != nullptr) {
        *kept = false;
    }
    if (take_cancel(req.id)) {
        return complete(req, std::unexpected{make_error(errc::kCancelled, "script cancelled")}, kept); // never resumed again
    }
    if (req.start_error) {
        return complete(req, std::unexpected{*req.start_error}, kept);
    }
    req.sliced = false;
    req.wake_frame = 0;
    req.wake_time.reset();
    req.woken = false;
    if (req.kind == request_kind::kTask && req.budget.sticky == sticky_stop::kNone) {
        req.budget.instructions = 0; // a task's instruction and wall limits bound each resume
        req.budget.active = {};
    }
    req.running = true;
    lua_State* from = running_.empty() || running_.back().thread == nullptr ? state_ : running_.back().thread;
    int status = LUA_OK;
    int nresults = 0;
    {
        const active_scope scope{*this, &req.budget, req.thread, &req, req.owner};
        status = lua_resume(req.thread, from, nargs, &nresults);
        credit_hook_progress(req.thread);
    }
    req.running = false;
    const sticky_stop stop = req.budget.sticky;

    if (status == LUA_YIELD) {
        lua_pop(req.thread, nresults);
        if (stop == sticky_stop::kNone) {
            if (req.wake_frame == 0 && !req.wake_time && req.waiting == wait_kind::kNone) {
                req.wake_frame = frame_ + 1; // a time slice ran out, or a plain coroutine.yield()
            }
            req.suspended_once = true;
            list_request(req); // the scheduler resumes it from now on (sets requests_dirty_)
            return std::nullopt;
        }
        return complete(req, std::unexpected{sticky_error(stop)}, kept);
    }
    // Done: nothing it leaves behind wakes sooner than requests_next_* say (what it woke, a joiner or a
    // waiter, set requests_dirty_ itself).
    if (status == LUA_OK) {
        // A stop wins even if the script swallowed it with pcall and returned normally.
        if (stop != sticky_stop::kNone) {
            return complete(req, std::unexpected{sticky_error(stop)}, kept);
        }
        return complete(req, nresults, kept);
    }
    // The dead coroutine's stack is still intact: take the traceback before the error object
    // (unless memory ran out: building it would need more).
    if (status != LUA_ERRMEM && stop != sticky_stop::kMemory) {
        luaL_traceback(state_, req.thread, nullptr, 0);
        pending_traceback = lua_tostring(state_, -1);
        lua_pop(state_, 1);
    }
    lua_xmove(req.thread, state_, 1);
    error err = take_lua_error(state_, status);
    if (stop != sticky_stop::kNone) {
        err.code = sticky_error(stop).code;
    }
    return complete(req, std::unexpected{std::move(err)}, kept);
}

result<value_list> sandbox_impl::complete(request_id id, result<int> outcome) {
    const auto it = requests_.find(id);
    if (it == requests_.end()) {
        return fail(errc::kNotFound, std::format("no request {}", id));
    }
    return complete(*it->second, std::move(outcome));
}

result<value_list> sandbox_impl::complete(request_record& req, result<int> outcome, bool* kept) {
    // Out of the scheduler first: nothing below (a fault abandoning its module's requests) may find
    // it. A record the caller wants to keep stays in unlisted_ until it is known to be reusable.
    const bool keepable = kept != nullptr && !req.listed;
    decltype(requests_)::node_type node;
    if (req.listed) {
        node = requests_.extract(req.id);
        req.listed = false;
    } else if (!keepable) {
        node = take_unlisted(req);
    }
    module_record* mod = req.kind == request_kind::kLoad ? record(req.owner.module) : nullptr;

    result<value_list> out = value_list{};
    if (!outcome) {
        out = std::unexpected{std::move(outcome).error()};
    } else if (req.kind == request_kind::kExec || req.kind == request_kind::kCall) {
        out = collect_results(req.thread, 1, *outcome);
    } else if (req.kind == request_kind::kLoad) {
        out = mod != nullptr ? complete_load(*mod, req.owner.revision, req.thread) : fail(errc::kNotFound, "the module was unloaded");
    } else if (req.kind == request_kind::kTask) {
        out = collect_results(req.thread, 1, *outcome);
        if (task_record* t = task(req.task_key)) {
            const int n = *outcome;
            auto packed = protect(state_, [&] {
                luaL_checkstack(state_, n + 3, "rhp: too many task results");
                lua_xmove(req.thread, state_, n); // the finished coroutine holds exactly its results
                t->results_ref = pack_top(state_, n);
            });
            if (!packed) {
                out = std::unexpected{std::move(packed).error()};
            }
        }
    }

    if (!out && out.error().where.empty()) {
        out.error().where = where_of(req);
    }
    const task_record* t = req.kind == request_kind::kTask ? task(req.task_key) : nullptr;
    const bool cancelled_task = t != nullptr && t->cancel_requested;
    // The coroutine closes (its to-be-closed variables run) and the request ends (a task's record
    // gets its outcome, joiners wake) before any policy undoes effects: undoing a task's own ledger
    // entry must not turn its failure into a cancellation. A coroutine that returned normally to a
    // caller that keeps it is only emptied: the caller's next handler runs in it.
    const bool reuse = keepable && out.has_value() && !closing_lua_ && lua_status(req.thread) == LUA_OK;
    if (reuse) {
        lua_settop(req.thread, 0);
    } else {
        close_thread(req, !out.has_value());
    }
    request_ended(req, &out, false);
    if (!out) {
        if (req.kind == request_kind::kExec) {
            (void)ledger_.revert_request(scratch_, req.id); // only this request's effects
        } else if (req.kind == request_kind::kLoad && mod != nullptr && mod->pending && mod->pending->revision == req.owner.revision) {
            abort_reload(*mod); // the old revision is untouched
        } else if (cancelled_task) {
            // a cancelled task: not a failure
        } else if (is_handler(req.kind)) {
            handler_failed_or_defer(req, out.error());
        } else {
            fault_or_defer(req.owner, out.error());
        }
    }
    if (req.suspended_once) {
        finished_.emplace_back(req.id, out);
    }
    if (reuse) {
        *kept = true;
        return out;
    }
    if (keepable) {
        node = take_unlisted(req);
    }
    if (!node.empty() && spare_requests_.size() < kSpareRequests) {
        spare_requests_.push_back(std::move(node)); // reserved in the constructor: no allocation
    }
    return out;
}

result<value_list> sandbox_impl::complete_load(module_record& mod, revision_id revision, lua_State* thread) {
    // on_save / on_restore of a reload that pump() completed still belong to the reload: checked.
    const operation_scope checked{*this};
    lua_State* L = state_;
    lua_xmove(thread, L, 1); // the exports table the loader returned
    if (mod.state == module_state::kLoading && mod.live.revision == revision) {
        mod.live.exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        mod.state = module_state::kActive;
        return value_list{};
    }
    if (!mod.pending || mod.pending->revision != revision) {
        lua_pop(L, 1);
        return fail(errc::kCancelled, "the reload was superseded");
    }
    mod.pending->exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Carry state over: new.on_restore(old.on_save()).
    const effect_owner old_owner{mod.id, mod.live.revision};
    const effect_owner new_owner{mod.id, revision};
    const int base = lua_gettop(L);
    lua_pushnil(L); // the saved state
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.exports_ref);
        lua_getfield(L, -1, "on_save");
        lua_remove(L, -2);
        if (lua_type(L, -1) == LUA_TFUNCTION) {
            if (auto saved = call_sync(old_owner, 0, 1); !saved) {
                lua_settop(L, base);
                saved.error().where = std::format("{}.on_save", mod.name);
                return std::unexpected{std::move(saved).error()};
            }
            lua_replace(L, base + 1);
        } else {
            lua_pop(L, 1);
        }
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, mod.pending->exports_ref);
    lua_getfield(L, -1, "on_restore");
    lua_remove(L, -2);
    if (lua_type(L, -1) == LUA_TFUNCTION) {
        lua_pushvalue(L, base + 1);
        if (auto restored = call_sync(new_owner, 1, 0); !restored) {
            lua_settop(L, base);
            restored.error().where = std::format("{}.on_restore", mod.name);
            return std::unexpected{std::move(restored).error()};
        }
    } else {
        lua_pop(L, 1);
    }
    lua_settop(L, base);

    // Swap: the old revision goes, the new one is live.
    const revision_id old_revision = mod.live.revision;
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == old_revision; },
                     "its module revision was replaced by a reload");
    (void)ledger_.revert_revision(mod.id, old_revision);
    release(mod.live);
    mod.live = std::move(*mod.pending);
    mod.pending.reset();
    if (mod.pending_source) {
        mod.history.push_back(std::move(*mod.pending_source));
        mod.pending_source.reset();
    }
    while (mod.history.size() > std::max<std::size_t>(options_.limits.revisions, 1)) {
        mod.history.pop_front();
    }
    mod.state = module_state::kActive;
    mod.fault.reset();
    return value_list{};
}

void sandbox_impl::close_thread(request_record& req, bool failed) noexcept {
    if (failed) {
        // Runs the pending to-be-closed variables of a coroutine that didn't return normally.
        (void)protect(state_, [&] {
            run_budget local;
            const active_scope scope{*this, running_.empty() ? &local : nullptr, nullptr, nullptr, req.owner};
            (void)lua_closethread(req.thread, state_);
        });
    }
    // A coroutine that returned normally is reusable: empty it and keep it for the next request.
    if (!failed && !closing_lua_ && lua_status(req.thread) == LUA_OK && spare_threads_.size() < kSpareRequests) {
        lua_settop(req.thread, 0);
        spare_threads_.emplace_back(req.thread, req.thread_ref); // reserved in the constructor: no allocation
    } else {
        luaL_unref(state_, LUA_REGISTRYINDEX, req.thread_ref);
    }
    req.thread_ref = kNoRef;
    req.thread = nullptr;
}

result<void> sandbox_impl::call_sync(const effect_owner& owner, int nargs, int nresults) {
    run_budget local;
    run_budget* budget = running_.empty() ? &local : nullptr;
    const int base = lua_gettop(state_) - nargs - 1;
    result<void> called;
    {
        const active_scope scope{*this, budget, nullptr, nullptr, owner};
        called = stack{state_}.call(nargs, nresults);
    }
    if (budget != nullptr && local.sticky != sticky_stop::kNone) {
        error stop = sticky_error(local.sticky);
        if (called) {
            lua_settop(state_, base);
            return std::unexpected{std::move(stop)};
        }
        called.error().code = stop.code;
    }
    return called;
}

value_list sandbox_impl::collect_results(lua_State* L, int first, int last) {
    value_list out;
    out.reserve(static_cast<std::size_t>(std::max(0, last - first + 1)));
    const stack s{L};
    for (int i = first; i <= last; ++i) {
        // Scalars in place (what stack::to_value makes of them, without a result<value> each).
        switch (lua_type(L, i)) {
        case LUA_TNIL: out.emplace_back(); continue;
        case LUA_TBOOLEAN: out.emplace_back(lua_toboolean(L, i) != 0); continue;
        case LUA_TNUMBER:
            if (lua_isinteger(L, i) != 0) {
                out.emplace_back(static_cast<std::int64_t>(lua_tointeger(L, i)));
            } else {
                out.emplace_back(static_cast<double>(lua_tonumber(L, i)));
            }
            continue;
        default: break;
        }
        auto v = s.to_value(i);
        if (v) {
            out.push_back(std::move(*v));
        } else {
            out.emplace_back(std::format("{}: {}", luaL_typename(L, i), lua_topointer(L, i)));
        }
    }
    return out;
}

// ---- the end of a request ---------------------------------------------------------------------------

void sandbox_impl::request_ended(request_record& req, const result<value_list>* outcome, bool abandoned) noexcept {
    stop_waiting(req);
    if (debugger_ && debugger_->step && debugger_->step->request == req.id) {
        debugger_->step.reset(); // a step that ran off the end of its request
        rearm_all();
    }
    if (req.resume_ref != kNoRef) {
        luaL_unref(state_, LUA_REGISTRYINDEX, req.resume_ref);
        req.resume_ref = kNoRef;
    }
    if (req.schedule_key != 0) {
        if (const auto it = schedule_.find(req.schedule_key); it != schedule_.end() && it->second.active == req.id) {
            it->second.active = {};
        }
    }
    if (req.kind == request_kind::kTask) {
        finish_task(req, outcome, abandoned);
    }
}

// ---- handler failures ----------------------------------------------------------------------------

void sandbox_impl::handler_failed_or_defer(const request_record& req, error err) {
    pending_failure f;
    f.owner = req.owner;
    f.kind = req.kind;
    f.source = req.source;
    f.handler_seq = req.handler_seq;
    // The state's memory is shared: a module that exhausted it would keep failing every handler.
    f.policy = req.budget.sticky == sticky_stop::kMemory ? handler_error_policy::kFault : req.policy;
    f.err = std::move(err);
    if (running_.empty()) {
        apply_failure(std::move(f));
    } else {
        pending_failures_.push_back(std::move(f)); // undo nothing while a run is active
    }
}

void sandbox_impl::apply_failure(pending_failure f) {
    ++handler_failures_;
    const module_record* mod = record(f.owner.module);
    handler_failure report;
    report.request = f.owner.request;
    report.module = f.owner.module;
    report.module_name = mod != nullptr ? mod->name : std::string{};
    switch (f.kind) {
    case request_kind::kFrame: report.kind = handler_kind::kFrame; break;
    case request_kind::kEvent: report.kind = handler_kind::kEvent; break;
    case request_kind::kTask: report.kind = handler_kind::kTask; break;
    default: report.kind = handler_kind::kTimer; break;
    }
    report.source = f.source;
    report.handler = f.handler_seq;
    report.action = f.policy;
    report.err = f.err;
    switch (f.policy) {
    case handler_error_policy::kFault: fault(f.owner, f.err); break;
    case handler_error_policy::kRemove:
        (void)ledger_.revert_request(f.owner.module, f.owner.request);
        if (f.handler_seq != 0) {
            (void)ledger_.revert_entry(f.handler_seq);
        }
        break;
    case handler_error_policy::kReport: (void)ledger_.revert_request(f.owner.module, f.owner.request); break;
    }
    // Lua hears about it through rhp.handler_failed, except about its own handlers' failures.
    if (f.source != kHandlerFailedEvent) {
        value::map info;
        info.emplace_back(value{"module"}, value{report.module_name});
        info.emplace_back(value{"kind"}, value{std::string{to_string(report.kind)}});
        info.emplace_back(value{"source"}, value{report.source});
        info.emplace_back(value{"id"}, value{static_cast<std::int64_t>(report.handler)});
        info.emplace_back(value{"action"}, value{std::string{to_string(report.action)}});
        info.emplace_back(value{"code"}, value{std::string{to_string(report.err.code)}});
        info.emplace_back(value{"message"}, value{report.err.message});
        info.emplace_back(value{"where"}, value{report.err.where});
        info.emplace_back(value{"traceback"}, value{report.err.traceback});
        (void)queue_script_event(kHandlerFailedEvent, module_id{}, value_list{value{std::move(info)}});
    }
    failure_reports_.push_back(std::move(report));
}

void sandbox_impl::report_failures() {
    for (auto& f : std::exchange(failure_reports_, {})) {
        if (options_.on_handler_error) {
            options_.on_handler_error(f);
        } else {
            output_for(f.request, f.module,
                       std::format("[handler failed] {} ({} {}): {} ({})", f.module_name.empty() ? "?" : f.module_name, f.kind, f.source, f.err, f.action));
        }
    }
}

void sandbox_impl::output_for(request_id request, module_id mod, std::string_view line) {
    if (options_.on_output) {
        options_.on_output(request, mod, line);
    } else if (options_.output) {
        options_.output(line);
    } else {
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
    }
}

// ---- faults --------------------------------------------------------------------------------------

void sandbox_impl::fault_or_defer(const effect_owner& owner, error err) {
    if (running_.empty()) {
        fault(owner, std::move(err));
    } else {
        pending_faults_.emplace_back(owner, std::move(err));
    }
}

void sandbox_impl::fault(const effect_owner& owner, error err) {
    module_record* mod = record(owner.module);
    if (mod == nullptr) {
        return;
    }
    if (mod->scratch) {
        // Scratch code faults only its own request's effects (earlier exec effects stay).
        if (owner.request) {
            abandon_requests([&](const request_record& r) { return r.id == owner.request; }, std::format("the script faulted: {}", err));
            (void)ledger_.revert_request(scratch_, owner.request);
        } else {
            (void)ledger_.revert(scratch_);
        }
        return;
    }
    if (mod->pending && owner.revision == mod->pending->revision) {
        abort_reload(*mod); // a fault of the incoming revision fails the reload; the live one stays
        return;
    }
    if (owner.revision && owner.revision != mod->live.revision) {
        return; // a revision that was already replaced
    }
    if (mod->state != module_state::kActive && mod->state != module_state::kLoading) {
        return;
    }
    abandon_requests([&](const request_record& r) { return r.owner.module == mod->id; }, "its module faulted");
    abort_reload(*mod);
    auto report = ledger_.revert(mod->id);
    if (!report.clean()) {
        err.message += std::format(" (revert left {} effect(s) in place)", report.failures.size());
    }
    mod->state = module_state::kFaulted;
    mod->fault = std::move(err);
}

void sandbox_impl::abort_reload(module_record& mod) noexcept {
    if (!mod.pending) {
        return;
    }
    const revision_id revision = mod.pending->revision;
    try {
        abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == revision; },
                         "the reload was abandoned");
        (void)ledger_.revert_revision(mod.id, revision);
    } catch (...) { // out of memory while reporting: the revision's effects are still owned by the ledger
    }
    release(*mod.pending);
    mod.pending.reset();
    mod.pending_source.reset();
}

void sandbox_impl::release(module_instance& instance) noexcept {
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.exports_ref);
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.env_ref);
    instance.exports_ref = kNoRef;
    instance.env_ref = kNoRef;
}

// ---- deferred work -----------------------------------------------------------------------------------

bool sandbox_impl::defer_if_running(std::function<void()> op) {
    if (running_.empty()) {
        return false;
    }
    deferred_.push_back(std::move(op));
    return true;
}

void sandbox_impl::drain() {
    if (!running_.empty()) {
        return;
    }
    // Nothing queued (the usual case: twice per call, exec and pump): no lock, no swaps. Every list
    // the body below works through is in this test; a cancel queued by another thread sets the flag.
    if (!cancel_ids_pending_.load(std::memory_order_acquire) && pending_faults_.empty() && pending_failures_.empty() && deferred_.empty() &&
        collected_tasks_.empty() && failure_reports_.empty() && listener_calls_.empty() && finished_.empty()) {
        return;
    }
    std::vector<request_id> cancels;
    {
        const std::scoped_lock lock{inbox_mutex_};
        cancels.swap(cancel_ids_);
        cancel_ids_pending_.store(false, std::memory_order_release);
    }
    for (const request_id id : cancels) {
        if (const auto it = requests_.find(id); it != requests_.end() && !it->second->running) {
            (void)complete(id, std::unexpected{make_error(errc::kCancelled, "script cancelled")});
        }
    }
    for (auto& [owner, err] : std::exchange(pending_faults_, {})) {
        fault(owner, std::move(err));
    }
    for (auto& f : std::exchange(pending_failures_, {})) {
        apply_failure(std::move(f));
    }
    for (auto& op : std::exchange(deferred_, {})) {
        op();
    }
    for (const std::uint64_t key : std::exchange(collected_tasks_, {})) {
        if (task_record* t = task(key)) {
            if (t->handles > 0) {
                --t->handles;
            }
            if (t->handles == 0 && t->finished) {
                luaL_unref(state_, LUA_REGISTRYINDEX, t->results_ref);
                tasks_.erase(key);
            }
        }
    }
    // Last: these callbacks may re-enter the sandbox.
    report_failures();
    call_listeners();
    if (options_.on_result) {
        for (auto& [id, r] : std::exchange(finished_, {})) {
            options_.on_result(id, r);
        }
    } else {
        finished_.clear();
    }
}

// ---- the frame ---------------------------------------------------------------------------------------

void sandbox_impl::resume_ready() {
    const steady::time_point now = script_now();
    if (!requests_dirty_ && frame_ < requests_next_frame_ && now < requests_next_wake_) {
        return; // every suspended request sleeps on: no walk over them
    }
    std::vector<request_id> ready;
    for (const auto& [id, req] : requests_) {
        if (!req->running && (req->woken || (req->wake_frame != 0 && frame_ >= req->wake_frame) || (req->wake_time && now >= *req->wake_time))) {
            ready.push_back(id);
        }
    }
    // Round robin from the request after the one resumed last, so with slicing on a busy request
    // can't take every slice.
    std::ranges::rotate(ready, std::ranges::upper_bound(ready, last_resumed_));
    for (const request_id id : ready) {
        if (slice_deadline_ && steady::now() >= *slice_deadline_) {
            requests_dirty_ = true;
            return; // the rest stay ready for the next pump()
        }
        if (const auto it = requests_.find(id); it != requests_.end() && !it->second->running) {
            last_resumed_ = id;
            request_record& req = *it->second;
            const int nargs = req.start_args >= 0 ? std::exchange(req.start_args, -1) : 0; // a task's first resume
            (void)step(req, nargs);
        }
    }
    requests_dirty_ = false;
    requests_next_frame_ = std::numeric_limits<std::uint64_t>::max();
    requests_next_wake_ = steady::time_point::max();
    for (const auto& [id, req] : requests_) {
        if (req->running) {
            continue;
        }
        if (req->woken) {
            requests_next_frame_ = 0; // woken during this pass: resumes at the next one
        }
        if (req->wake_frame != 0) {
            requests_next_frame_ = std::min(requests_next_frame_, req->wake_frame);
        }
        if (req->wake_time) {
            requests_next_wake_ = std::min(requests_next_wake_, *req->wake_time);
        }
    }
}

// ---- operations ----------------------------------------------------------------------------------

result<void> sandbox_impl::install_lib(std::string_view name, c_function build, std::string (*describe)(role), tunables_fn collect, value (*api)(role)) {
    drain();
    result<void> out{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
        stack{L}.push_string(name);
        if (lua_rawget(L, -2) != LUA_TNIL) {
            out = fail(errc::kAlreadyLoaded, std::format("the global '{}' already exists", name), std::string{name});
            lua_pop(L, 2);
            return;
        }
        lua_pop(L, 1);
        lua_pushcfunction(L, build);
        lua_call(L, 0, 1);
        stack{L}.set_field(-2, name);
        lua_pop(L, 1);
    });
    if (!glue) {
        return std::unexpected{std::move(glue).error()};
    }
    if (out) {
        describers_.push_back(describe);
        api_describers_.push_back(api);
        collect(tunables_);
    }
    return out;
}

result<std::vector<tunable_info>> sandbox_impl::tunables(std::string_view prefix) {
    std::vector<tunable_info> out;
    for (const tunable_info& t : tunables_) {
        if (path_matches(t.path, prefix)) {
            out.push_back(t);
            out.back().writable = t.writable && allows(options_.caller_role, role::kPatch);
        }
    }
    if (out.empty() && !prefix.empty()) {
        return fail(errc::kNotFound, std::format("no variable is or starts with '{}'", prefix), "tunables");
    }
    auto read = protect(state_, [&] {
        lua_State* L = state_;
        for (tunable_info& t : out) {
            push_lib_path(L, t.path);
            auto v = stack{L}.to_value(-1);
            t.current = v ? std::move(*v) : value{}; // a value with no wire form (a handle): nil
            lua_pop(L, 1);
        }
    });
    if (!read) {
        return std::unexpected{std::move(read).error()};
    }
    return out;
}

result<void> sandbox_impl::tune(std::string_view path, const value& v) {
    const auto known = std::ranges::find(tunables_, path, &tunable_info::path);
    if (known == tunables_.end()) {
        return fail(errc::kNotFound, std::format("no variable '{}'", path), "tune");
    }
    if (!known->writable) {
        return fail(errc::kForbidden, "read-only", std::string{path});
    }
    const operation_scope operation{*this};
    drain();
    result<void> out{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        lua_pushcfunction(L, &lua_tune_thunk);
        stack{L}.push_string(path);
        stack{L}.push_value(v);
        request_record& req = start_request(request_kind::kExec, effect_owner{scratch_}, "tune", 2, true);
        if (auto done = step(req, 2); done && !*done) {
            out = std::unexpected{std::move(*done).error()};
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

result<value_list> sandbox_impl::exec(std::string_view source, std::string_view chunk_name, bool cached) {
    const operation_scope operation{*this};
    drain();
    std::string chunk;
    chunk.reserve(chunk_name.size() + 1);
    chunk.push_back('=');
    chunk.append(chunk_name);
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        const slice_scope slice{*this};
        if (auto compiled = compile(source, chunk, record(scratch_)->live.env_ref, cached); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        request_record& req = start_request(request_kind::kExec, effect_owner{scratch_}, {}, 0, true);
        if (auto done = step(req, 0)) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

result<std::string> sandbox_impl::compile_module(std::string_view name, std::string_view source) {
    if (!utils::is_dotted_name(name)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a module name (dotted lowercase, e.g. combat.low_grav)", name));
    }
    const std::string chunk = std::format("@{}", name);
    result<std::string> out = std::string{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const int status = luaL_loadbufferx(L, source.data(), source.size(), chunk.c_str(), "t");
        if (status != LUA_OK) {
            error err = take_lua_error(L, status);
            if (err.code == errc::kRuntime) {
                err.code = errc::kCompile;
            }
            out = std::unexpected{std::move(err)};
            return;
        }
        std::string dumped;
        if (lua_dump(L, &dump_writer, &dumped, 0) != 0 || dumped.empty()) {
            out = fail(errc::kRuntime, "the compiled chunk couldn't be dumped");
        } else {
            out = std::move(dumped);
        }
        lua_pop(L, 1);
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out && out.error().where.empty()) {
        out.error().where = std::string{name};
    }
    return out;
}

result<module_id> sandbox_impl::load(std::string_view name, std::string_view source, std::string_view bytecode) {
    const operation_scope operation{*this};
    drain();
    if (!utils::is_dotted_name(name)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a module name (dotted lowercase, e.g. combat.low_grav)", name));
    }
    if (const auto existing = find(name)) {
        auto reloaded = reload(*existing, source, bytecode);
        if (!reloaded) {
            return std::unexpected{std::move(reloaded).error()};
        }
        return *existing;
    }
    const module_id id = ids_.next();
    {
        module_record mod;
        mod.id = id;
        mod.name = std::string{name};
        mod.state = module_state::kLoading;
        mod.revisions_made = 1;
        mod.live.revision = revision_id{1};
        mod.history.push_back(revision_source{revision_id{1}, std::string{source}, source_hash(source)});
        modules_.emplace(id, std::move(mod));
    }

    const std::string chunk = std::format("@{}", name);
    bool compiled_ok = false;
    std::optional<error> failure;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        module_record& mod = *record(id);
        mod.live.env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod.live.env_ref, false, bytecode); !compiled) {
            failure = std::move(compiled).error();
            return;
        }
        compiled_ok = true;
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, mod.live.revision}, mod.name, 2, true);
        if (auto done = step(req, 2); done && !*done) {
            failure = std::move(*done).error();
        }
    });
    if (!glue && !failure) {
        failure = std::move(glue).error();
        if (compiled_ok) {
            fault_or_defer(effect_owner{id, revision_id{1}}, *failure);
        }
    }
    if (failure && !compiled_ok) {
        if (module_record* mod = record(id)) {
            release(mod->live);
        }
        modules_.erase(id);
    }
    drain();
    if (failure) {
        if (failure->where.empty()) {
            failure->where = std::string{name};
        }
        return std::unexpected{std::move(*failure)};
    }
    return id;
}

result<revision_id> sandbox_impl::reload(module_id id, std::string_view source, std::string_view bytecode) {
    const operation_scope operation{*this};
    const module_record* found = record(id);
    if (found == nullptr || found->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id, src = std::string{source}] { (void)reload(id, src); })) { // parses: the bytecode's view won't live that long
        return revision_id{};
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state == module_state::kLoading) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is still loading", mod->name), mod->name);
    }
    if (mod->pending) {
        return fail(errc::kInvalidArgument, std::format("a reload of module '{}' is already loading", mod->name), mod->name);
    }
    const revision_id revision{++mod->revisions_made};
    const std::string chunk = std::format("@{}", mod->name);
    result<revision_id> out = revision;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        mod->pending = module_instance{revision};
        mod->pending_source = revision_source{revision, std::string{source}, source_hash(source)};
        mod->pending->env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod->pending->env_ref, false, bytecode); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->pending->env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, revision}, mod->name, 2, true);
        if (auto done = step(req, 2)) {
            if (!*done) {
                out = std::unexpected{std::move(*done).error()};
            }
        } else {
            out = revision_id{}; // still loading: the swap happens in a later pump()
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out) {
        if (module_record* still = record(id); still != nullptr && still->pending && still->pending->revision == revision) {
            abort_reload(*still);
        }
        if (out.error().where.empty()) {
            out.error().where = std::string{record(id) != nullptr ? record(id)->name : std::string{}};
        }
    }
    drain();
    return out;
}

result<revision_id> sandbox_impl::rollback(module_id id, std::size_t steps) {
    const module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (steps == 0 || steps >= mod->history.size()) {
        return fail(errc::kOutOfRange, std::format("module '{}' keeps {} revision(s); can't go back {}", mod->name, mod->history.size(), steps),
                    mod->name);
    }
    const std::string source = mod->history[mod->history.size() - 1 - steps].source;
    return reload(id, source);
}

result<value_list> sandbox_impl::call(module_id id, std::string_view function, std::span<const value> args) {
    const operation_scope operation{*this};
    drain();
    module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state != module_state::kActive) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is {}", mod->name, mod->state), mod->name);
    }
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        const int base = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
        stack{L}.push_string(function);
        lua_gettable(L, -2);
        lua_remove(L, -2);
        if (lua_type(L, -1) != LUA_TFUNCTION) {
            out = fail(errc::kNotFound, std::format("module '{}' exports no function '{}'", mod->name, function), mod->name);
            lua_settop(L, base);
            return;
        }
        luaL_checkstack(L, static_cast<int>(args.size()) + 2, "rhp: too many arguments");
        for (const auto& arg : args) {
            stack{L}.push_value(arg);
        }
        request_record& req = start_request(request_kind::kCall, effect_owner{id, mod->live.revision}, mod->name, static_cast<int>(args.size()), true);
        req.label.push_back('.'); // "module.function", built in the pooled record's string: no allocation once warm
        req.label.append(function);
        if (auto done = step(req, static_cast<int>(args.size()))) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

revert_report sandbox_impl::revert_module(module_record& mod) {
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id; }, "its module was reverted");
    abort_reload(mod);
    auto report = ledger_.revert(mod.id);
    if (!mod.scratch && (mod.state == module_state::kActive || mod.state == module_state::kLoading)) {
        mod.state = module_state::kReverted;
    }
    return report;
}

result<revert_report> sandbox_impl::revert(module_id id) {
    if (record(id) == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)revert_module(*mod);
            }
        })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = revert_module(*mod);
    drain();
    return report;
}

revert_report sandbox_impl::unload_module(module_record& mod) {
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef) {
        // on_unload errors are ignored: the module is going away regardless.
        (void)protect(state_, [&] {
            lua_State* L = state_;
            const int base = lua_gettop(L);
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.exports_ref);
            lua_getfield(L, -1, "on_unload");
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TFUNCTION) {
                (void)call_sync(effect_owner{mod.id, mod.live.revision}, 0, 0);
            }
            lua_settop(L, base);
        });
    }
    auto report = revert_module(mod);
    const module_id id = mod.id;
    release(mod.live);
    forget_proxy(id);
    for (auto& [other_id, other] : modules_) {
        other.live.dependencies.erase(id);
        if (other.pending) {
            other.pending->dependencies.erase(id);
        }
    }
    modules_.erase(id);
    return report;
}

result<revert_report> sandbox_impl::unload(module_id id, bool forced) {
    const operation_scope operation{*this};
    const module_record* found = record(id);
    if (found == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (found->scratch) {
        return fail(errc::kInvalidArgument, "the scratch module can't be unloaded; revert it instead", found->name);
    }
    if (!forced) {
        if (const auto dependents = dependents_of(id); !dependents.empty()) {
            std::string names;
            for (const auto& name : dependents) {
                names += names.empty() ? name : ", " + name;
            }
            return fail(errc::kHasDependents, std::format("module '{}' is required by {} (unload them first, or force)", found->name, names),
                        found->name);
        }
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)unload_module(*mod);
            }
        })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = unload_module(*mod);
    drain();
    return report;
}

result<void> sandbox_impl::checkpoint(std::string_view tag) {
    checkpoints_.insert_or_assign(std::string{tag}, ledger::mark());
    return {};
}

result<revert_report> sandbox_impl::revert_to(std::string_view tag) {
    const auto it = checkpoints_.find(tag);
    if (it == checkpoints_.end()) {
        return fail(errc::kNotFound, std::format("no checkpoint '{}'", tag));
    }
    const std::uint64_t mark = it->second;
    const auto apply = [this, mark] {
        auto report = ledger_.revert_after(mark);
        std::erase_if(checkpoints_, [mark](const auto& entry) { return entry.second > mark; });
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    auto report = apply();
    drain();
    return report;
}

revert_report sandbox_impl::revert_all() {
    const operation_scope operation{*this};
    const auto apply = [this] {
        revert_report report;
        std::vector<module_id> ids;
        for (const auto& [id, mod] : modules_) {
            if (!mod.scratch) {
                ids.push_back(id);
            }
        }
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            if (module_record* mod = record(*it)) {
                report += unload_module(*mod);
            }
        }
        report += revert_module(*record(scratch_));
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    auto report = apply();
    drain();
    return report;
}

result<module_id> sandbox_impl::find(std::string_view name) const {
    for (const auto& [id, mod] : modules_) {
        if (!mod.scratch && mod.name == name) {
            return id;
        }
    }
    return fail(errc::kNotFound, std::format("no module '{}'", name));
}

std::optional<module_info> sandbox_impl::status(module_id id) const {
    const module_record* mod = record(id);
    if (mod == nullptr) {
        return std::nullopt;
    }
    module_info info{mod->id, mod->name, mod->state, mod->scratch, ledger_.count(id), ledger_.irreversible_count(id), mod->fault};
    info.revision = mod->live.revision;
    info.source_hash = mod->history.empty() ? 0 : mod->history.back().hash;
    info.revisions = mod->history.size();
    info.reloading = mod->pending.has_value();
    info.dependencies.assign(mod->live.dependencies.begin(), mod->live.dependencies.end());
    return info;
}

std::vector<module_info> sandbox_impl::list() const {
    std::vector<module_info> out;
    out.reserve(modules_.size());
    for (const auto& [id, mod] : modules_) {
        out.push_back(*status(id));
    }
    return out;
}

void sandbox_impl::cancel() noexcept {
    cancel_running_.store(true, std::memory_order_release);
}

void sandbox_impl::cancel(request_id request) noexcept {
    try {
        const std::scoped_lock lock{inbox_mutex_};
        cancel_ids_.push_back(request);
        cancel_ids_pending_.store(true, std::memory_order_release);
    } catch (...) { // out of memory: the request keeps running
    }
}

void sandbox_impl::pump() {
    thread_.store(std::this_thread::get_id(), std::memory_order_release);
    drain();
    ++frame_;
    decltype(inbox_) inbox;
    {
        const std::scoped_lock lock{inbox_mutex_};
        inbox.swap(inbox_);
    }
    const std::vector<queued_script_event> published = std::exchange(script_events_, {});
    (void)protect(state_, [&] {
        const slice_scope slice{*this};
        for (auto& [event, args] : inbox) {
            deliver_now(event, event_pusher{&args, [](stack& s, const void* data) {
                                                return (*static_cast<const std::function<int(stack&)>*>(data))(s);
                                            }},
                        module_id{}, nullptr);
        }
        for (const queued_script_event& e : published) {
            deliver_now(e.name, event_pusher{&e.args, [](stack& s, const void* data) {
                                                 const auto& values = *static_cast<const value_list*>(data);
                                                 luaL_checkstack(s.state(), static_cast<int>(values.size()) + 2, "rhp: too many event values");
                                                 for (const value& v : values) {
                                                     s.push_value(v);
                                                 }
                                                 return static_cast<int>(values.size());
                                             }},
                        e.publisher, &e.args);
        }
        fire_schedule();
        wake_async();
        resume_ready();
    });
    drain();
}

result<bool> sandbox_impl::collect_idle(std::chrono::microseconds budget) {
    if (budget <= std::chrono::microseconds::zero()) {
        return false;
    }
    bool finished = false;
    auto stepped = protect(state_, [&] {
        const steady::time_point deadline = steady::now() + budget;
        do {
            const int step = lua_gc(state_, LUA_GCSTEP, std::size_t{0});
            if (step < 0) {
                break; // the collector is stopped (a finalizer called this)
            }
            finished = step == 1;
        } while (!finished && gc_mode_ == gc_mode::kIncremental && steady::now() < deadline);
    });
    if (!stepped) {
        return std::unexpected{std::move(stepped).error()};
    }
    return finished;
}

std::size_t sandbox_impl::suspended() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(requests_, [](const auto& entry) { return !entry.second->running; }));
}

std::string sandbox_impl::stubs() const {
    std::string out = script::stubs::rhp_api(options_.caller_role);
    for (const auto describe : describers_) {
        out += '\n';
        out += describe(options_.caller_role);
    }
    return out;
}

} // namespace detail

// ---- sandbox (public) ------------------------------------------------------------------------------

sandbox::sandbox(sandbox_options options) : impl_(std::make_unique<detail::sandbox_impl>(std::move(options))) {}

sandbox::~sandbox() = default;
sandbox::sandbox(sandbox&&) noexcept = default;
sandbox& sandbox::operator=(sandbox&&) noexcept = default;

result<void> sandbox::install_lib(std::string_view name, c_function build, stub_fn describe, detail::tunables_fn collect, api_fn api) {
    return impl_->install_lib(name, build, describe, collect, api);
}

result<std::vector<tunable_info>> sandbox::tunables(std::string_view prefix) {
    return impl_->tunables(prefix);
}

result<void> sandbox::tune(std::string_view path, const value& v) {
    return impl_->tune(path, v);
}

result<std::vector<std::uint32_t>> sandbox::set_breakpoints(std::string_view source, std::span<const std::uint32_t> lines) {
    return impl_->set_breakpoints(source, lines);
}

void sandbox::debug_pause() {
    impl_->debug_pause();
}

void sandbox::debug_reset() {
    impl_->debug_reset();
}

std::vector<debug_stop> sandbox::paused() const {
    return impl_->paused();
}

result<void> sandbox::debug_resume(request_id request, step_mode mode) {
    return impl_->debug_resume(request, mode);
}

result<std::vector<debug_frame>> sandbox::debug_stack(request_id request) {
    return impl_->debug_stack(request);
}

result<std::vector<debug_variable>> sandbox::debug_variables(request_id request, std::uint32_t frame, debug_scope scope, std::span<const std::string> path) {
    return impl_->debug_variables(request, frame, scope, path);
}

result<debug_variable> sandbox::debug_evaluate(request_id request, std::uint32_t frame, std::string_view expression) {
    return impl_->debug_evaluate(request, frame, expression);
}

result<void> sandbox::start_profile(profile_options options) {
    return impl_->start_profile(options);
}

profile_report sandbox::profile() const {
    return impl_->profile();
}

profile_report sandbox::stop_profile() {
    return impl_->stop_profile();
}

void sandbox::start_metering() {
    impl_->start_metering();
}

void sandbox::stop_metering() {
    impl_->stop_metering();
}

run_meter sandbox::meter() {
    return impl_->meter();
}

void sandbox::reset_peak() noexcept {
    impl_->reset_peak();
}

result<void> sandbox::collect_garbage(int cycles) {
    return impl_->collect_garbage(cycles);
}

result<void> sandbox::set_gc_mode(gc_mode mode) {
    return impl_->set_gc_mode(mode);
}

result<void> sandbox::start_coverage() {
    return impl_->start_coverage();
}

coverage_report sandbox::coverage() const {
    return impl_->coverage();
}

coverage_report sandbox::stop_coverage() {
    return impl_->stop_coverage();
}

result<void> sandbox::enable_testing(testing_options options) {
    return impl_->enable_testing(std::move(options));
}

std::optional<std::chrono::steady_clock::time_point> sandbox::next_due() const {
    return impl_->next_due();
}

result<value_list> sandbox::call_point(std::string_view id, std::span<const value> args) {
    return impl_->call_point(id, args);
}

result<void> sandbox::fire_event(std::string_view name, std::span<const value> args) {
    return impl_->fire_event(name, args);
}

result<value_list> sandbox::exec(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name);
}

result<value_list> sandbox::exec_cached(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name, true);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source) {
    return impl_->load(name, source);
}

result<revision_id> sandbox::reload(module_id mod, std::string_view source) {
    return impl_->reload(mod, source);
}

result<std::string> sandbox::compile_module(std::string_view name, std::string_view source) {
    return impl_->compile_module(name, source);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source, trusted_bytecode code) {
    return impl_->load(name, source, code.bytes());
}

result<revision_id> sandbox::reload(module_id mod, std::string_view source, trusted_bytecode code) {
    return impl_->reload(mod, source, code.bytes());
}

result<revision_id> sandbox::rollback(module_id mod, std::size_t steps) {
    return impl_->rollback(mod, steps);
}

result<value_list> sandbox::call(module_id mod, std::string_view function, std::span<const value> args) {
    return impl_->call(mod, function, args);
}

result<revert_report> sandbox::revert(module_id mod) {
    return impl_->revert(mod);
}

result<revert_report> sandbox::unload(module_id mod) {
    return impl_->unload(mod, false);
}

result<revert_report> sandbox::unload(module_id mod, force_t) {
    return impl_->unload(mod, true);
}

result<void> sandbox::checkpoint(std::string_view tag) {
    return impl_->checkpoint(tag);
}

result<revert_report> sandbox::revert_to(std::string_view tag) {
    return impl_->revert_to(tag);
}

revert_report sandbox::revert_all() {
    return impl_->revert_all();
}

result<module_id> sandbox::find(std::string_view name) const {
    return impl_->find(name);
}

std::optional<module_info> sandbox::status(module_id mod) const {
    return impl_->status(mod);
}

std::vector<module_info> sandbox::list() const {
    return impl_->list();
}

module_id sandbox::scratch_module() const noexcept {
    return impl_->scratch_module();
}

void sandbox::cancel() noexcept {
    impl_->cancel();
}

void sandbox::cancel(request_id request) noexcept {
    impl_->cancel(request);
}

void sandbox::pump() {
    impl_->pump();
}

result<bool> sandbox::collect_idle(std::chrono::microseconds budget) {
    return impl_->collect_idle(budget);
}

request_id sandbox::last_request() const noexcept {
    return impl_->last_request();
}

std::size_t sandbox::suspended() const noexcept {
    return impl_->suspended();
}

bool sandbox::pending(request_id request) const noexcept {
    return impl_->pending(request);
}

std::uint64_t sandbox::frame() const noexcept {
    return impl_->frame();
}

role sandbox::caller_role() const noexcept {
    return impl_->caller_role();
}

std::size_t sandbox::memory_used() const noexcept {
    return impl_->memory_used();
}

const ledger& sandbox::effects() const noexcept {
    return impl_->effects();
}

value sandbox::api() const {
    return impl_->api();
}

std::string sandbox::stubs() const {
    return impl_->stubs();
}

Rhp::subscription sandbox::on_script_event(std::string_view name, script_event_fn fn) {
    return impl_->on_script_event(name, std::move(fn));
}

sandbox_stats sandbox::stats() const {
    sandbox_stats s = impl_->stats();
    s.bytecode_loaded = impl_->bytecode_loaded();
    s.bytecode_rejected = impl_->bytecode_rejected();
    return s;
}

std::string_view bytecode_build() {
    static const std::string build = detail::make_bytecode_build();
    return build;
}

async_leftovers sandbox::release_async() {
    return impl_->release_async();
}

} // namespace Rhp::script
