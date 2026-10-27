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
#include <rhp/script/puc_lua/keys.hpp>
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

void check_function(lua_State* L, int index, std::string_view where) {
    if (lua_type(L, index) != LUA_TFUNCTION) {
        const stack s{L};
        s.raise(make_error(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(index)), std::string{where}));
    }
}

std::uint64_t checked_id(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto id = s.to_integer(index);
    if (!id || *id <= 0) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an id, got {}", s.type_name(index)), std::string{where}));
    }
    return static_cast<std::uint64_t>(*id);
}

namespace {

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
    impl_of(L).remove_by_id(L, checked_id(L, 1, "rhp.off"));
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
    running_.reserve(kSpareRequests);  // likewise; the first sandbox::call can take call_unprotected's path
    call_keys_.reserve(kCallKeys);
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
    open_buffer_library(L); // rhp.buffer, and the span and buffer types (buffer.cpp)
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
    output_for(current_.request, current_.module, line);
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
    return env_ref_of(*mod, current_.revision);
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

// ---- output ------------------------------------------------------------------------------------

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

// ---- the frame and cancels ------------------------------------------------------------------------

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

} // namespace detail

} // namespace Rhp::script
